const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

// Configurar dotenv
dotenv.config();

// Inicializar la app
const app = express();
app.use(express.json());

// Configurar multer para subida de PDFs
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = "./pdfs";
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir);
    }
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (path.extname(file.originalname).toLowerCase() === ".pdf") {
      cb(null, true);
    } else {
      cb(new Error("Solo se permiten archivos PDF"), false);
    }
  },
});

// Conexión a MongoDB Atlas
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Conectado a MongoDB Atlas"))
  .catch((err) => console.error("❌ Error de conexión:", err));

// Esquema para contadores (autoincremento)
const CounterSchema = new mongoose.Schema({
  _id: String,
  seq: Number,
});
const Counter = mongoose.model("Counter", CounterSchema);

// Esquema para Admins
const AdminSchema = new mongoose.Schema({
  adminId: { type: Number, unique: true },
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: "Admin" },
  secretKey: { type: String, required: true },
});
const Admin = mongoose.model("Admin", AdminSchema);

// Esquema para Users
const UserSchema = new mongoose.Schema({
  userId: { type: Number, unique: true },
  businessName: { type: String, required: true },
  contactNumber: { type: String, required: true },
  ruc: { type: String, required: true, match: /^[0-9]{11}$/ },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  pdfCount: { type: Number, default: 0 },
  role: { type: String, default: "User" },
  status: { type: String, enum: ["active", "inactive"], default: "active" },
});
const User = mongoose.model("User", UserSchema);

// Esquema para DeletedUsers
const DeletedUserSchema = new mongoose.Schema({
  userId: { type: Number, unique: true },
  businessName: { type: String, required: true },
  contactNumber: { type: String, required: true },
  ruc: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  pdfCount: { type: Number, default: 0 },
  role: { type: String, default: "User" },
  status: { type: String, default: "inactive" },
});
const DeletedUser = mongoose.model("DeletedUser", DeletedUserSchema);

// Esquema para PDFs
const PdfSchema = new mongoose.Schema({
  pdfId: { type: Number, unique: true },
  userId: { type: Number, required: true },
  fullName: { type: String, required: true },
  email: { type: String, required: true },
  uploadDate: { type: Date, default: Date.now },
  pdfName: { type: String, required: true },
  pdfPath: { type: String, required: true },
});
const Pdf = mongoose.model("Pdf", PdfSchema);

// Función para obtener el siguiente ID autoincrementable
async function getNextSequence(name) {
  const counter = await Counter.findOneAndUpdate(
    { _id: name },
    { $inc: { seq: 1 } },
    { new: true, upsert: true }
  );
  return counter.seq;
}

// Función para verificar unicidad del correo
async function checkEmailUniqueness(email, excludeUserId) {
  const userExists = await User.findOne({
    email,
    userId: { $ne: excludeUserId },
  });
  const deletedUserExists = await DeletedUser.findOne({ email });
  return userExists || deletedUserExists;
}

// Función para sincronizar pdfCount
async function syncPdfCount(userId) {
  const pdfCount = await Pdf.countDocuments({ userId });
  await User.findOneAndUpdate({ userId }, { pdfCount });
  return pdfCount;
}

// Middleware para verificar JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token requerido" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Token inválido" });
    req.user = user;
    next();
  });
}

// Middleware para verificar rol de Admin
function isAdmin(req, res, next) {
  if (req.user.role !== "Admin") {
    return res
      .status(403)
      .json({ message: "Acceso denegado, solo para Admins" });
  }
  next();
}

// Rutas

// Login Admin
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;
  const admin = await Admin.findOne({ email });
  if (!admin) return res.status(404).json({ message: "Cuenta no encontrada" });

  const isMatch = await bcrypt.compare(password, admin.password);
  if (!isMatch)
    return res.status(401).json({ message: "Contraseña incorrecta" });

  const token = jwt.sign(
    { id: admin._id, role: admin.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
  res.json({ message: "Login exitoso", token });
});

// Login User
app.post("/api/user/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: "Cuenta no encontrada" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch)
    return res.status(401).json({ message: "Contraseña incorrecta" });

  const token = jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
  res.json({ message: "Login exitoso", token });
});

// Crear Admin (requiere clave secreta)
app.post("/api/admin", async (req, res) => {
  const { fullName, email, password, secretKey } = req.body;
  if (secretKey !== process.env.ADMIN_SECRET_KEY) {
    return res.status(403).json({ message: "Clave secreta incorrecta" });
  }

  const emailExists = await checkEmailUniqueness(email);
  if (emailExists) {
    return res.status(400).json({ message: "El correo ya está registrado" });
  }

  const adminId = await getNextSequence("adminId");
  const hashedPassword = await bcrypt.hash(password, 10);

  const admin = new Admin({
    adminId,
    fullName,
    email,
    password: hashedPassword,
    secretKey,
    role: "Admin",
  });

  try {
    await admin.save();
    res.status(201).json({ message: "Admin creado exitosamente" });
  } catch (err) {
    res
      .status(400)
      .json({ message: "Error al crear admin", error: err.message });
  }
});

// CRUD Usuarios (solo Admins)
app.post("/api/users", authenticateToken, isAdmin, async (req, res) => {
  const { businessName, contactNumber, ruc, email, password } = req.body;

  const emailExists = await checkEmailUniqueness(email);
  if (emailExists) {
    return res.status(400).json({ message: "El correo ya está registrado" });
  }

  const userId = await getNextSequence("userId");
  const hashedPassword = await bcrypt.hash(password, 10);

  const user = new User({
    userId,
    businessName,
    contactNumber,
    ruc,
    email,
    password: hashedPassword,
    pdfCount: 0,
    role: "User",
    status: "active",
  });

  try {
    await user.save();
    res.status(201).json({ message: "Usuario creado exitosamente" });
  } catch (err) {
    res
      .status(400)
      .json({ message: "Error al crear usuario", error: err.message });
  }
});

app.get("/api/users", authenticateToken, isAdmin, async (req, res) => {
  const users = await User.find().select("-password");
  res.json(users);
});

app.put("/api/users/:userId", authenticateToken, isAdmin, async (req, res) => {
  const { userId } = req.params;
  const { businessName, contactNumber, ruc, email, password } = req.body;

  // Preparar los campos a actualizar
  const updates = {};

  try {
    // Buscar el usuario actual
    const currentUser = await User.findOne({ userId });
    if (!currentUser) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    // Agregar campos a actualizar solo si han cambiado
    if (businessName && businessName !== currentUser.businessName) {
      updates.businessName = businessName;
    }
    if (contactNumber && contactNumber !== currentUser.contactNumber) {
      updates.contactNumber = contactNumber;
    }
    if (ruc && ruc !== currentUser.ruc) {
      if (!/^[0-9]{11}$/.test(ruc)) {
        return res
          .status(400)
          .json({ message: "El RUC debe tener 11 dígitos numéricos" });
      }
      updates.ruc = ruc;
    }
    if (email && email !== currentUser.email) {
      const emailExists = await checkEmailUniqueness(email, userId);
      if (emailExists) {
        return res
          .status(400)
          .json({ message: "El correo ya está registrado" });
      }
      updates.email = email;
    }
    if (password) {
      const isSamePassword = await bcrypt.compare(
        password,
        currentUser.password
      );
      if (!isSamePassword) {
        updates.password = await bcrypt.hash(password, 10);
      }
    }

    // Si no hay cambios, devolver el usuario sin actualizar
    if (Object.keys(updates).length === 0) {
      const userResponse = {
        userId: currentUser.userId,
        businessName: currentUser.businessName,
        contactNumber: currentUser.contactNumber,
        ruc: currentUser.ruc,
        email: currentUser.email,
        password: currentUser.password, // Incluye la contraseña hasheada
        pdfCount: currentUser.pdfCount,
        role: currentUser.role,
        status: currentUser.status,
      };
      return res.json({
        message: "No se realizaron cambios",
        user: userResponse,
      });
    }

    // Actualizar el usuario
    const user = await User.findOneAndUpdate(
      { userId },
      { $set: updates },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    // Preparar la respuesta incluyendo la contraseña hasheada
    const userResponse = {
      userId: user.userId,
      businessName: user.businessName,
      contactNumber: user.contactNumber,
      ruc: user.ruc,
      email: user.email,
      password: user.password, // Incluye la contraseña hasheada
      pdfCount: user.pdfCount,
      role: user.role,
      status: user.status,
    };

    res.json({
      message: "Usuario actualizado exitosamente",
      user: userResponse,
    });
  } catch (err) {
    res
      .status(400)
      .json({ message: "Error al actualizar usuario", error: err.message });
  }
});

app.delete(
  "/api/users/:userId",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    const { userId } = req.params;
    const user = await User.findOne({ userId });
    if (!user)
      return res.status(404).json({ message: "Usuario no encontrado" });

    const deletedUser = new DeletedUser({
      ...user.toObject(),
      status: "inactive",
    });
    await deletedUser.save();
    await User.deleteOne({ userId });

    res.json({ message: "Usuario movido a inactivos" });
  }
);

app.post(
  "/api/users/restore/:userId",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    const { userId } = req.params;
    const deletedUser = await DeletedUser.findOne({ userId });
    if (!deletedUser)
      return res
        .status(404)
        .json({ message: "Usuario inactivo no encontrado" });

    const emailExists = await User.findOne({ email: deletedUser.email });
    if (emailExists) {
      return res
        .status(400)
        .json({ message: "El correo ya está registrado en usuarios activos" });
    }

    const user = new User({
      ...deletedUser.toObject(),
      status: "active",
    });
    await user.save();
    await DeletedUser.deleteOne({ userId });

    res.json({ message: "Usuario restaurado exitosamente" });
  }
);

// Subir PDF (solo Users)
app.post("/api/pdfs", authenticateToken, async (req, res) => {
  if (req.user.role !== "User") {
    return res
      .status(403)
      .json({ message: "Acceso denegado, solo para Users" });
  }

  upload.single("pdf")(req, res, async (err) => {
    if (err) {
      return res.status(400).json({ message: err.message });
    }

    if (!req.file) {
      return res
        .status(400)
        .json({ message: "No se proporcionó ningún archivo PDF" });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const pdfId = await getNextSequence("pdfId");
    user.pdfCount += 1;
    await user.save();

    const pdf = new Pdf({
      pdfId,
      userId: user.userId,
      fullName: user.businessName,
      email: user.email,
      pdfName: req.file.originalname,
      pdfPath: `pdfs/${req.file.filename}`,
    });

    try {
      await pdf.save();
      res.status(201).json({ message: "PDF subido exitosamente" });
    } catch (err) {
      res
        .status(400)
        .json({ message: "Error al subir PDF", error: err.message });
    }
  });
});

// Obtener PDFs por usuario
app.get("/api/pdfs", authenticateToken, async (req, res) => {
  if (req.user.role !== "User") {
    return res
      .status(403)
      .json({ message: "Acceso denegado, solo para Users" });
  }

  const user = await User.findById(req.user.id).select("-password");
  if (!user) return res.status(404).json({ message: "Usuario no encontrado" });

  const pdfs = await Pdf.find({ userId: user.userId });
  const pdfCount = await syncPdfCount(user.userId);

  res.json({
    pdfCount: pdfCount,
    pdfs: pdfs,
  });
});

// Obtener datos del admin logueado (nombre completo)
app.get("/api/admin/profile", authenticateToken, isAdmin, async (req, res) => {
  try {
    const admin = await Admin.findById(req.user.id).select("fullName email");
    if (!admin) {
      return res.status(404).json({ message: "Admin no encontrado" });
    }
    res.json({
      fullName: admin.fullName,
      email: admin.email,
    });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error al obtener perfil", error: err.message });
  }
});

// Obtener lista de usuarios eliminados/inactivos
app.get("/api/users/deleted", authenticateToken, isAdmin, async (req, res) => {
  try {
    const deletedUsers = await DeletedUser.find().select("-password");
    res.json(deletedUsers);
  } catch (err) {
    res.status(500).json({
      message: "Error al obtener usuarios eliminados",
      error: err.message,
    });
  }
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor corriendo en puerto ${PORT}`));
