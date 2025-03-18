// backend/server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Configurações iniciais
dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

// Conexão com o banco de dados
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('MongoDB conectado!'))
  .catch(err => console.log(err));

// Modelo de Usuário
const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String
});
const User = mongoose.model('User', UserSchema);

// Modelo de Caso Pericial
const CaseSchema = new mongoose.Schema({
    title: String,
    description: String,
    status: { type: String, enum: ['Em andamento', 'Finalizado', 'Arquivado'], default: 'Em andamento' },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now }
});
const Case = mongoose.model('Case', CaseSchema);

// Rota de Registro de Usuário
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: 'Usuário registrado com sucesso!' });
    } catch (err) {
        res.status(400).json({ error: 'Erro ao registrar usuário' });
    }
});

// Rota de Login de Usuário
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Erro no servidor' });
    }
});

// Middleware de autenticação
const authMiddleware = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Acesso negado' });
    try {
        const verified = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Token inválido' });
    }
};

// Rotas para CRUD de Casos Periciais
// Criar um novo caso
app.post('/api/cases', authMiddleware, async (req, res) => {
    const { title, description } = req.body;
    try {
        const newCase = new Case({ title, description, createdBy: req.user.userId });
        await newCase.save();
        res.status(201).json(newCase);
    } catch (err) {
        res.status(400).json({ error: 'Erro ao criar caso pericial' });
    }
});

// Listar todos os casos
app.get('/api/cases', authMiddleware, async (req, res) => {
    try {
        const cases = await Case.find().populate('createdBy', 'name');
        res.json(cases);
    } catch (err) {
        res.status(500).json({ error: 'Erro ao buscar casos' });
    }
});

// Atualizar um caso por ID
app.put('/api/cases/:id', authMiddleware, async (req, res) => {
    try {
        const updatedCase = await Case.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(updatedCase);
    } catch (err) {
        res.status(400).json({ error: 'Erro ao atualizar caso' });
    }
});

// Deletar um caso por ID
app.delete('/api/cases/:id', authMiddleware, async (req, res) => {
    try {
        await Case.findByIdAndDelete(req.params.id);
        res.json({ message: 'Caso deletado com sucesso!' });
    } catch (err) {
        res.status(500).json({ error: 'Erro ao deletar caso' });
    }
});

// Rotas básicas
app.get('/', (req, res) => {
    res.send('API Rodando...');
});

// Inicialização do servidor
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
