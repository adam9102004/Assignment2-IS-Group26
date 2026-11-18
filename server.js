require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const CryptographicService = require('./CryptographicService');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

const upload = multer({ limits: { fileSize: 5 * 1024 * 1024 } });

const cryptoService = new CryptographicService();
const JWT_SECRET = process.env.JWT_SECRET || 'super-jwt-secret-key';

const USERS_DB = [];
const markDatabase = [];
const sharedDataStore = [];
const accessRequests = [];

function initializeDefaultUsers() {
  const defaultAccounts = [
    { username: 'Dr_Smith', password: 'teacherpassword123', role: 'teacher', name: 'Dr. Smith (Faculty)', studentId: null },
    { username: 'atan', password: 'studentpassatan', role: 'student', name: 'Atan Bin Ahmad', studentId: 'atan' }
  ];

  defaultAccounts.forEach(acc => {
    const keys = cryptoService.generateUserKeys();
    USERS_DB.push({ ...acc, publicKey: keys.publicKey, privateKey: keys.privateKey });
  });
}
initializeDefaultUsers();

app.post('/api/v1/auth/signup', (req, res) => {
  const { username, password, role, name, studentId } = req.body;
  if (!username || !password || !role || !name) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }
  if (USERS_DB.find(u => u.username === username)) {
    return res.status(409).json({ error: 'Username already exists.' });
  }

  const assignedStudentId = role === 'student' ? (studentId || username) : null;
  const userKeys = cryptoService.generateUserKeys();

  const newUser = { username, password, role, name, studentId: assignedStudentId, publicKey: userKeys.publicKey, privateKey: userKeys.privateKey };
  USERS_DB.push(newUser);

  const token = jwt.sign({ username: newUser.username, role: newUser.role, name: newUser.name, studentId: newUser.studentId }, JWT_SECRET, { expiresIn: '30m' });
  res.status(201).json({ success: true, accessToken: token, user: newUser });
});

app.post('/api/v1/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS_DB.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

  const tokenPayload = { username: user.username, role: user.role, name: user.name, studentId: user.studentId || null };
  const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '30m' });
  res.json({ accessToken: token, user: tokenPayload });
});

const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token missing.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token.' });
    req.user = user;
    next();
  });
};

app.get('/api/v1/users', verifyToken, (req, res) => {
  res.json(USERS_DB.map(u => ({ username: u.username, name: u.name, role: u.role })));
});

// Teacher / User Mark & Combined File Upload Entry
app.post('/api/v1/teacher/marks', verifyToken, upload.single('documentFile'), (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ error: 'Teacher privileges required.' });
  const { studentId, subjectCode, grade } = req.body;
  
  if (!studentId || !subjectCode || !grade) {
    return res.status(400).json({ error: 'Missing required mark fields.' });
  }

  const encGrade = cryptoService.encryptTier1(`Student: ${studentId} | Subject: ${subjectCode} | Grade: ${grade}`);
  
  let encryptedFilePayload = null;
  if (req.file) {
    const fileBase64 = req.file.buffer.toString('base64');
    const encFile = cryptoService.encryptTier1(fileBase64);
    encryptedFilePayload = {
      filename: req.file.originalname,
      mimetype: req.file.mimetype,
      data: encFile.data,
      iv: encFile.iv,
      cipher: encFile.cipher
    };
  }

  const record = {
    recordId: Math.random().toString(36).substring(2, 9),
    studentId,
    subjectCode,
    gradeData: encGrade.data,
    gradeIv: encGrade.iv,
    gradeCipher: encGrade.cipher,
    document: encryptedFilePayload,
    submittedBy: req.user.username,
    createdAt: new Date().toISOString()
  };

  markDatabase.push(record);
  res.status(201).json({ success: true, message: 'Mark and encrypted document stored securely.', recordId: record.recordId });
});

app.get('/api/v1/student/results', verifyToken, (req, res) => {
  const records = markDatabase.filter(r => r.studentId === req.user.studentId);
  const results = records.map(r => {
    let decryptedFile = null;
    if (r.document) {
      const decryptedBase64 = cryptoService.decryptTier1(r.document.data, r.document.iv);
      decryptedFile = {
        filename: r.document.filename,
        mimetype: r.document.mimetype,
        dataUri: `data:${r.document.mimetype};base64,${decryptedBase64}`
      };
    }
    return {
      recordId: r.recordId,
      subjectCode: r.subjectCode,
      details: cryptoService.decryptTier1(r.gradeData, r.gradeIv),
      cipherUsed: r.gradeCipher,
      document: decryptedFile,
      createdAt: r.createdAt
    };
  });
  res.json({ results });
});

// Universal Access Request (Any role to any role)
app.post('/api/v1/access/request', verifyToken, (req, res) => {
  const { ownerUsername, reason } = req.body;
  const owner = USERS_DB.find(u => u.username === ownerUsername);
  if (!owner) return res.status(404).json({ error: 'Owner not found.' });

  const requestObj = {
    requestId: Math.random().toString(36).substring(2, 9),
    requester: req.user.username,
    owner: ownerUsername,
    reason: reason || 'Document review',
    status: 'Pending',
    createdAt: new Date().toISOString()
  };
  accessRequests.push(requestObj);
  res.status(201).json({ success: true, requestId: requestObj.requestId });
});

app.get('/api/v1/access/requests', verifyToken, (req, res) => {
  res.json({ requests: accessRequests.filter(r => r.owner === req.user.username && r.status === 'Pending') });
});

// Approval Route with Combined Text Note & File Upload (Unified Encryption)
app.post('/api/v1/access/approve', verifyToken, upload.single('approvalFile'), (req, res) => {
  const { requestId, writtenNote } = req.body;
  if (!requestId) {
    return res.status(400).json({ error: 'Request ID is missing.' });
  }

  const reqObj = accessRequests.find(r => r.requestId === requestId && r.owner === req.user.username);
  if (!reqObj) {
    return res.status(404).json({ error: 'Request not found.' });
  }

  const requester = USERS_DB.find(u => u.username === reqObj.requester);
  if (!requester) {
    return res.status(404).json({ error: 'Requester not found.' });
  }

  reqObj.status = 'Approved';

  // 1. Encrypt written note and/or context in the same encryption process
  const noteContent = writtenNote ? `Note: ${writtenNote}` : `Approved access for request ${requestId} (Reason: ${reqObj.reason}).`;
  const rawSymmetricKeyHex = cryptoService.aesKey.toString('hex');
  const cipherIv = require('crypto').randomBytes(16);
  
  const cipher = require('crypto').createCipheriv('aes-256-cbc', Buffer.from(rawSymmetricKeyHex, 'hex'), cipherIv);
  let encryptedPayload = cipher.update(noteContent, 'utf8', 'hex');
  encryptedPayload += cipher.final('hex');

  // 2. Encrypt optional uploaded file using the same shared symmetric key pipeline
  let encryptedFilePayload = null;
  if (req.file) {
    const fileBase64 = req.file.buffer.toString('base64');
    const fileCipher = require('crypto').createCipheriv('aes-256-cbc', Buffer.from(rawSymmetricKeyHex, 'hex'), cipherIv);
    let encFileHex = fileCipher.update(fileBase64, 'utf8', 'hex');
    encFileHex += fileCipher.final('hex');

    encryptedFilePayload = {
      filename: req.file.originalname,
      mimetype: req.file.mimetype,
      data: encFileHex
    };
  }

  // 3. Asymmetrically wrap the symmetric key and IV into a SINGLE field package
  const singleWrappedKeyPackage = cryptoService.encryptSymmetricKeyForRecipient(rawSymmetricKeyHex, cipherIv.toString('hex'), requester.publicKey);

  const sharePackage = {
    shareId: Math.random().toString(36).substring(2, 9),
    sender: req.user.username,
    recipient: reqObj.requester,
    encryptedData: encryptedPayload,
    iv: cipherIv.toString('hex'),
    singleKeyPackage: singleWrappedKeyPackage,
    document: encryptedFilePayload,
    createdAt: new Date().toISOString()
  };

  sharedDataStore.push(sharePackage);
  res.json({ 
    success: true, 
    message: 'Request approved with unified text and file encryption! Copy the single key package below.',
    outOfBandPackage: {
      shareId: sharePackage.shareId,
      singleKeyPackage: singleWrappedKeyPackage
    }
  });
});

// Single-Field Decryption Route
app.post('/api/v1/share/decrypt-manual', verifyToken, (req, res) => {
  const { manualKeyPackage } = req.body;
  if (!manualKeyPackage) {
    return res.status(400).json({ error: 'Please provide the single key package string.' });
  }

  const myUser = USERS_DB.find(u => u.username === req.user.username);

  try {
    // 1. Unwrap the single key package using user's private key to extract symmetric key and IV
    const unwrapped = cryptoService.decryptSymmetricKeyWithPrivate(manualKeyPackage.trim(), myUser.privateKey);
    const rawKeyHex = unwrapped.key;
    const ivHex = unwrapped.iv;

    // Find the package matching this decrypted key or search shared store
    const pkg = sharedDataStore.find(s => s.recipient === req.user.username && s.iv === ivHex);
    if (!pkg) {
      return res.status(404).json({ error: 'Matching shared encrypted package not found for this key.' });
    }

    // 2. Decrypt text payload
    const decipher = require('crypto').createDecipheriv('aes-256-cbc', Buffer.from(rawKeyHex, 'hex'), Buffer.from(ivHex, 'hex'));
    let text = decipher.update(pkg.encryptedData, 'hex', 'utf8');
    text += decipher.final('utf8');

    // 3. Decrypt attached file if present using same key/IV
    let decryptedFile = null;
    if (pkg.document) {
      const fileDecipher = require('crypto').createDecipheriv('aes-256-cbc', Buffer.from(rawKeyHex, 'hex'), Buffer.from(ivHex, 'hex'));
      let decryptedBase64 = fileDecipher.update(pkg.document.data, 'hex', 'utf8');
      decryptedBase64 += fileDecipher.final('utf8');

      decryptedFile = {
        filename: pkg.document.filename,
        mimetype: pkg.document.mimetype,
        dataUri: `data:${pkg.document.mimetype};base64,${decryptedBase64}`
      };
    }

    res.json({ success: true, decryptedContent: text, document: decryptedFile });
  } catch (err) {
    res.status(400).json({ error: 'Decryption failed: Invalid private key or malformed key package.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`[Server] running on http://localhost:${PORT}`));