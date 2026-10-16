import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import mongoose from 'mongoose'
import multer from 'multer'
import { Readable } from 'node:stream'
import { randomBytes, scryptSync, createHmac, timingSafeEqual } from 'node:crypto'

const app = express()
app.use(cors())
app.use(express.json())
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 30 * 1024 * 1024 } })
let ebookBucket
const jwtSecret = process.env.JWT_SECRET || randomBytes(48).toString('hex')
const sessionCookie = 'bookstack_session'
const sessionCookieOptions = { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', path: '/', maxAge: 7 * 24 * 60 * 60 * 1000 }

const bookSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  author: { type: String, required: true, trim: true },
  genre: { type: String, default: 'Fiction' },
  isbn: { type: String, trim: true },
  total: { type: Number, required: true, min: 1 },
  available: { type: Number, required: true, min: 0 },
  isEbook: { type: Boolean, default: false },
  ebookFileId: { type: mongoose.Schema.Types.ObjectId, default: null },
  ebookFileName: { type: String, default: '' },
}, { timestamps: true })
const Book = mongoose.model('Book', bookSchema)
const memberSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, trim: true, lowercase: true, unique: true },
  memberSince: { type: Date, default: Date.now },
  active: { type: Boolean, default: true },
}, { timestamps: true })
const Member = mongoose.model('Member', memberSchema)
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  name: { type: String, required: true, trim: true },
  role: { type: String, enum: ['admin', 'member'], default: 'member' },
  member: { type: mongoose.Schema.Types.ObjectId, ref: 'Member', default: null },
}, { timestamps: true })
const User = mongoose.model('User', userSchema)
const loanSchema = new mongoose.Schema({
  book: { type: mongoose.Schema.Types.ObjectId, ref: 'Book', required: true },
  member: { type: mongoose.Schema.Types.ObjectId, ref: 'Member', required: true },
  checkedOutAt: { type: Date, default: Date.now },
  dueAt: { type: Date, required: true },
  returnedAt: { type: Date, default: null },
}, { timestamps: true })
const Loan = mongoose.model('Loan', loanSchema)
const requestSchema = new mongoose.Schema({
  book: { type: mongoose.Schema.Types.ObjectId, ref: 'Book', required: true },
  member: { type: mongoose.Schema.Types.ObjectId, ref: 'Member', required: true },
  status: { type: String, enum: ['pending', 'approving', 'approved', 'rejected'], default: 'pending' },
  requestedAt: { type: Date, default: Date.now },
  reviewedAt: { type: Date, default: null },
  loan: { type: mongoose.Schema.Types.ObjectId, ref: 'Loan', default: null },
}, { timestamps: true })
const BookRequest = mongoose.model('BookRequest', requestSchema)

function createSession(user, res) {
  const profile = { id: user._id.toString(), username: user.username, name: user.name, role: user.role, memberId: user.member?.toString() || null, exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60 }
  const encoded = Buffer.from(JSON.stringify(profile)).toString('base64url')
  const signature = createHmac('sha256', jwtSecret).update(encoded).digest('base64url')
  const token = `${encoded}.${signature}`
  const flags = `Path=/; HttpOnly; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}${sessionCookieOptions.secure ? '; Secure' : ''}`
  res.setHeader('Set-Cookie', `${sessionCookie}=${token}; ${flags}`)
  return profile
}
function readCookie(req, name) {
  const prefix = `${name}=`
  const item = (req.headers.cookie || '').split(';').map(value => value.trim()).find(value => value.startsWith(prefix))
  return item ? decodeURIComponent(item.slice(prefix.length)) : null
}
function verifySession(token) {
  const [encoded, signature] = String(token || '').split('.')
  if (!encoded || !signature) throw new Error('Invalid session')
  const expected = createHmac('sha256', jwtSecret).update(encoded).digest()
  const supplied = Buffer.from(signature, 'base64url')
  if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) throw new Error('Invalid session')
  const profile = JSON.parse(Buffer.from(encoded, 'base64url').toString())
  if (!profile.exp || profile.exp < Date.now() / 1000) throw new Error('Expired session')
  return profile
}
function hashPassword(password, salt = randomBytes(16).toString('hex')) {
  const hash = scryptSync(password, salt, 64).toString('hex')
  return `${salt}:${hash}`
}
function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || '').split(':')
  if (!salt || !hash) return false
  const actual = Buffer.from(hashPassword(password, salt).split(':')[1], 'hex')
  const expected = Buffer.from(hash, 'hex')
  return actual.length === expected.length && timingSafeEqual(actual, expected)
}
function requireAuth(req, res, next) {
  try {
    const token = readCookie(req, sessionCookie)
    if (!token) return res.status(401).json({ message: 'Sign in to continue' })
    req.auth = verifySession(token)
    next()
  } catch { res.status(401).json({ message: 'Your session expired. Sign in again.' }) }
}
function requireAdmin(req, res, next) {
  if (req.auth?.role !== 'admin') return res.status(403).json({ message: 'Admin access required' })
  next()
}

app.get('/api/health', (_req, res) => res.json({ ok: true, database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' }))
app.post('/api/auth/register', async (req, res) => {
  const name = String(req.body.name || '').trim()
  const username = String(req.body.username || '').trim().toLowerCase()
  const email = String(req.body.email || '').trim().toLowerCase()
  const password = String(req.body.password || '')
  if (!name || !/^[a-z0-9._-]{3,24}$/.test(username) || !/^\S+@\S+\.\S+$/.test(email) || password.length < 8) return res.status(400).json({ message: 'Enter a name, valid email, username (3–24 letters/numbers), and password (at least 8 characters)' })
  let member
  try {
    const passwordHash = hashPassword(password)
    member = await Member.create({ name, email })
    const user = await User.create({ name, username, email, passwordHash, role: 'member', member: member._id })
    res.status(201).json({ user: createSession(user, res) })
  } catch (error) {
    if (member) await Member.deleteOne({ _id: member._id }).catch(() => {})
    res.status(409).json({ message: error.code === 11000 ? 'Username or email is already registered' : 'Could not create account' })
  }
})
app.post('/api/auth/login', async (req, res) => {
  try {
    const identity = String(req.body.identity || req.body.username || '').trim().toLowerCase()
    const user = await User.findOne({ $or: [{ username: identity }, { email: identity }] })
    if (!user || !verifyPassword(String(req.body.password || ''), user.passwordHash)) return res.status(401).json({ message: 'Incorrect username/email or password' })
    res.json({ user: createSession(user, res) })
  } catch { res.status(500).json({ message: 'Could not sign in' }) }
})
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: req.auth }))
app.post('/api/auth/logout', (_req, res) => { res.setHeader('Set-Cookie', `${sessionCookie}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${sessionCookieOptions.secure ? '; Secure' : ''}`); res.status(204).end() })
app.get('/api/books', async (_req, res) => {
  try { res.json(await Book.find().sort({ createdAt: -1 })) }
  catch (error) { res.status(503).json({ message: 'Could not load books', error: error.message }) }
})
app.post('/api/books', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { title, author, genre, isbn, total } = req.body
    const book = await Book.create({ title, author, genre, isbn, total, available: total })
    res.status(201).json(book)
  } catch (error) { res.status(400).json({ message: 'Could not add book', error: error.message }) }
})
app.post('/api/books/ebook', requireAuth, requireAdmin, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'Choose a PDF file to upload' })
  if (req.file.mimetype !== 'application/pdf' || req.file.buffer.subarray(0, 5).toString() !== '%PDF-') return res.status(400).json({ message: 'Only valid PDF files are accepted' })
  let fileId
  try {
    const stream = ebookBucket.openUploadStream(req.file.originalname, { contentType: 'application/pdf' })
    fileId = stream.id
    await new Promise((resolve, reject) => { stream.once('finish', resolve); stream.once('error', reject); Readable.from([req.file.buffer]).pipe(stream) })
    const book = await Book.create({ title: req.body.title, author: req.body.author, genre: req.body.genre || 'Fiction', isbn: req.body.isbn || '', total: 1, available: 1, isEbook: true, ebookFileId: fileId, ebookFileName: req.file.originalname })
    res.status(201).json(book)
  } catch (error) {
    if (fileId) await ebookBucket.delete(fileId).catch(() => {})
    res.status(400).json({ message: 'Could not upload e-book', error: error.message })
  }
})
app.get('/api/books/:id/ebook', requireAuth, async (req, res) => {
  try {
    const book = await Book.findById(req.params.id)
    if (!book?.isEbook || !book.ebookFileId) return res.status(404).json({ message: 'E-book not found' })
    if (req.auth.role !== 'admin') {
      const hasAccess = await Loan.exists({ member: req.auth.memberId, book: book._id, returnedAt: null })
      if (!hasAccess) return res.status(403).json({ message: 'An approved active loan is required to open this e-book' })
    }
    res.set('Content-Type', 'application/pdf')
    res.set('Content-Disposition', `inline; filename="${encodeURIComponent(book.ebookFileName || `${book.title}.pdf`)}"`)
    ebookBucket.openDownloadStream(book.ebookFileId).on('error', () => { if (!res.headersSent) res.status(404).end() }).pipe(res)
  } catch (error) { res.status(400).json({ message: 'Could not open e-book', error: error.message }) }
})
app.patch('/api/books/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const book = await Book.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true })
    if (!book) return res.status(404).json({ message: 'Book not found' })
    res.json(book)
  } catch (error) { res.status(400).json({ message: 'Could not update book', error: error.message }) }
})
app.delete('/api/books/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const book = await Book.findByIdAndDelete(req.params.id)
    if (!book) return res.status(404).json({ message: 'Book not found' })
    if (book.ebookFileId) await ebookBucket.delete(book.ebookFileId).catch(() => {})
    res.status(204).end()
  } catch (error) { res.status(400).json({ message: 'Could not delete book', error: error.message }) }
})
app.get('/api/members', requireAuth, requireAdmin, async (_req, res) => {
  try { res.json(await Member.find().sort({ name: 1 })) }
  catch (error) { res.status(503).json({ message: 'Could not load members', error: error.message }) }
})
app.post('/api/members', requireAuth, requireAdmin, async (req, res) => {
  try {
    const member = await Member.create({ name: req.body.name, email: req.body.email })
    res.status(201).json(member)
  }
  catch (error) { res.status(400).json({ message: 'Could not add member', error: error.message }) }
})
app.delete('/api/members/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const hasActiveLoans = await Loan.exists({ member: req.params.id, returnedAt: null })
    if (hasActiveLoans) return res.status(409).json({ message: 'Return this member’s books before removing them' })
    const hasPendingRequests = await BookRequest.exists({ member: req.params.id, status: 'pending' })
    if (hasPendingRequests) return res.status(409).json({ message: 'Review this member’s pending requests before removing them' })
    const member = await Member.findByIdAndDelete(req.params.id)
    if (!member) return res.status(404).json({ message: 'Member not found' })
    await User.deleteOne({ member: member._id })
    res.status(204).end()
  } catch (error) { res.status(400).json({ message: 'Could not remove member', error: error.message }) }
})
app.get('/api/loans', requireAuth, async (req, res) => {
  try { const filter = { returnedAt: null }; if (req.auth.role !== 'admin') filter.member = req.auth.memberId; res.json(await Loan.find(filter).populate('book').populate('member').sort({ dueAt: 1 })) }
  catch (error) { res.status(503).json({ message: 'Could not load loans', error: error.message }) }
})
app.get('/api/requests', requireAuth, async (req, res) => {
  try {
    const filter = req.auth.role === 'admin' ? {} : { member: req.auth.memberId }
    res.json(await BookRequest.find(filter).populate('book').populate('member').populate('loan').sort({ requestedAt: -1 }))
  } catch (error) { res.status(503).json({ message: 'Could not load requests', error: error.message }) }
})
app.post('/api/requests', requireAuth, async (req, res) => {
  try {
    if (req.auth.role !== 'member' || !req.auth.memberId) return res.status(403).json({ message: 'Reader account required to request a book' })
    const member = await Member.findOne({ _id: req.auth.memberId, active: true })
    if (!member) return res.status(400).json({ message: 'Choose an active member' })
    const book = await Book.findOne({ _id: req.body.bookId, available: { $gt: 0 } })
    if (!book) return res.status(409).json({ message: 'This book is currently unavailable' })
    const alreadyRequested = await BookRequest.exists({ member: member._id, book: book._id, status: { $in: ['pending', 'approving'] } })
    if (alreadyRequested) return res.status(409).json({ message: 'You already have a pending request for this book' })
    const activeLoan = await Loan.exists({ member: member._id, book: book._id, returnedAt: null })
    if (activeLoan) return res.status(409).json({ message: 'You already have this book checked out' })
    const request = await BookRequest.create({ member: member._id, book: book._id })
    res.status(201).json(await BookRequest.findById(request._id).populate('book').populate('member'))
  } catch (error) { res.status(400).json({ message: 'Could not submit request', error: error.message }) }
})
app.patch('/api/requests/:id/review', requireAuth, requireAdmin, async (req, res) => {
  const action = req.body.action
  if (!['approve', 'reject'].includes(action)) return res.status(400).json({ message: 'Action must be approve or reject' })
  let reservedBookId
  let claimedRequest
  try {
    claimedRequest = await BookRequest.findOneAndUpdate({ _id: req.params.id, status: 'pending' }, { status: action === 'approve' ? 'approving' : 'rejected', reviewedAt: action === 'reject' ? new Date() : null }, { new: true })
    if (!claimedRequest) return res.status(404).json({ message: 'Pending request not found' })
    if (action === 'reject') return res.json(await BookRequest.findById(claimedRequest._id).populate('book').populate('member'))
    const book = await Book.findOneAndUpdate({ _id: claimedRequest.book, available: { $gt: 0 } }, { $inc: { available: -1 } }, { new: true })
    if (!book) {
      await BookRequest.updateOne({ _id: claimedRequest._id }, { status: 'pending', reviewedAt: null })
      return res.status(409).json({ message: 'No copies are currently available; request remains pending' })
    }
    reservedBookId = book._id
    const dueAt = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000)
    const loan = await Loan.create({ book: book._id, member: claimedRequest.member, dueAt })
    await BookRequest.updateOne({ _id: claimedRequest._id, status: 'approving' }, { status: 'approved', reviewedAt: new Date(), loan: loan._id })
    res.json(await BookRequest.findById(claimedRequest._id).populate('book').populate('member').populate('loan'))
  } catch (error) {
    if (reservedBookId) await Book.updateOne({ _id: reservedBookId }, { $inc: { available: 1 } })
    if (claimedRequest && action === 'approve') await BookRequest.updateOne({ _id: claimedRequest._id, status: 'approving' }, { status: 'pending', reviewedAt: null })
    res.status(400).json({ message: error.message || 'Could not review request' })
  }
})
app.post('/api/loans', requireAuth, requireAdmin, async (req, res) => {
  let reservedBookId
  try {
    const member = await Member.findOne({ _id: req.body.memberId, active: true })
    if (!member) return res.status(400).json({ message: 'Choose an active member' })
    const book = await Book.findOneAndUpdate({ _id: req.body.bookId, available: { $gt: 0 } }, { $inc: { available: -1 } }, { new: true })
    if (!book) return res.status(409).json({ message: 'Book not found or no copies are available' })
    reservedBookId = book._id
    const loan = await Loan.create({ book: book._id, member: member._id, dueAt: req.body.dueAt })
    res.status(201).json(await Loan.findById(loan._id).populate('book').populate('member'))
  } catch (error) {
    if (reservedBookId) await Book.updateOne({ _id: reservedBookId }, { $inc: { available: 1 } })
    res.status(400).json({ message: error.message || 'Could not create loan' })
  }
})
app.patch('/api/loans/:id/return', requireAuth, requireAdmin, async (req, res) => {
  try {
    const loan = await Loan.findOneAndUpdate({ _id: req.params.id, returnedAt: null }, { returnedAt: new Date() }, { new: true })
    if (!loan) return res.status(404).json({ message: 'Active loan not found' })
    await Book.updateOne({ _id: loan.book }, { $inc: { available: 1 } })
    res.json(loan)
  } catch (error) { res.status(400).json({ message: error.message || 'Could not return loan' }) }
})
app.patch('/api/loans/:id/reissue', requireAuth, requireAdmin, async (req, res) => {
  const days = Math.min(Math.max(Number(req.body.days) || 14, 1), 60)
  try {
    const loan = await Loan.findOne({ _id: req.params.id, returnedAt: null })
    if (!loan) return res.status(404).json({ message: 'Active loan not found' })
    loan.dueAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000)
    await loan.save()
    res.json(await Loan.findById(loan._id).populate('book').populate('member'))
  } catch (error) { res.status(400).json({ message: error.message || 'Could not renew loan' }) }
})

app.use((error, _req, res, _next) => {
  if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ message: 'PDF must be 30 MB or smaller' })
  if (error instanceof multer.MulterError) return res.status(400).json({ message: error.message })
  res.status(500).json({ message: 'Unexpected server error' })
})

const port = process.env.PORT || 4000
async function ensureAdminAccount() {
  const username = String(process.env.ADMIN_USERNAME || '').trim().toLowerCase()
  const password = String(process.env.ADMIN_PASSWORD || '')
  if (!username || password.length < 8) throw new Error('Set ADMIN_USERNAME and an ADMIN_PASSWORD of at least 8 characters in .env')
  const email = String(process.env.ADMIN_EMAIL || 'admin@folio.local').trim().toLowerCase()
  const passwordHash = hashPassword(password)
  await User.findOneAndUpdate({ username }, { $set: { username, email, name: 'Library Administrator', passwordHash, role: 'admin', member: null } }, { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true })
}
mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/folio_library')
  .then(async () => { ebookBucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, { bucketName: 'ebooks' }); await ensureAdminAccount(); app.listen(port, () => console.log(`BookStack API running on http://localhost:${port}`)) })
  .catch(error => { console.error('MongoDB connection failed:', error.message); process.exit(1) })
