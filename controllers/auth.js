const { response } = require('express')
const bcrypt = require('bcryptjs')

const Usuario = require('../models/usuario')
const { generarJWT } = require('../helpers/jwt')
const { googleVerify } = require('../helpers/google-verify')

const getMenu = (role = 'USER_ROLE') => {
  const menu = [
    {
      titulo: 'Dashboard',
      icono: 'mdi mdi-gauge',
      submenu: [
        { titulo: 'Dashboard', url: '/dashboard' },
        { titulo: 'ProgressBar', url: 'progress' },
        { titulo: 'Gráficas', url: 'grafica1' },
        { titulo: 'Promesas', url: 'promesas' },
        { titulo: 'Rxjs', url: 'rxjs' }
      ]
    },
    {
      titulo: 'Mantenimientos',
      icono: 'mdi mdi-folder-lock-open',
      submenu: [
        // { titulo: 'Usuarios', url: 'usuarios' },
        { titulo: 'Hospitales', url: 'hospitales' },
        { titulo: 'Médicos', url: 'medicos' }
      ]
    }
  ]

  if (role === 'ADMIN_ROLE') {
    menu[1].submenu.unshift({ titulo: 'Usuarios', url: 'usuarios' })
  }

  return menu
}

const login = async (req, res = response) => {
  const { email, password } = req.body

  try {
    // Verificar email
    const usuarioDB = await Usuario.findOne({ email })

    if (!usuarioDB) {
      return res.status(404).json({
        ok: false,
        msg: 'Email no encontrado'
      })
    }

    // Verificar contraseña
    const validPassword = bcrypt.compareSync(password, usuarioDB.password)
    if (!validPassword) {
      return res.status(400).json({
        ok: false,
        msg: 'Contraseña no válida'
      })
    }

    // Generar el TOKEN - JWT
    const token = await generarJWT(usuarioDB.id)

    res.json({
      ok: true,
      token,
      menu: getMenu(usuarioDB.role)
    })
  } catch (error) {
    console.log(error)
    res.status(500).json({
      ok: false,
      msg: 'Hable con el administrador'
    })
  }
}

const googleSignIn = async (req, res = response) => {
  const googleToken = req.body.token

  try {
    const { name, email, picture } = await googleVerify(googleToken)

    const usuarioDB = await Usuario.findOne({ email })
    let usuario

    if (!usuarioDB) {
      // si no existe el usuario
      usuario = new Usuario({
        nombre: name,
        email,
        password: '@@@',
        img: picture,
        google: true
      })
    } else {
      // existe usuario
      usuario = usuarioDB
      usuario.google = true
    }

    // Guardar en DB
    await usuario.save()

    // Generar el TOKEN - JWT
    const token = await generarJWT(usuario.id)

    res.json({
      ok: true,
      token,
      menu: getMenu(usuario.role)
    })
  } catch (error) {
    res.status(401).json({
      ok: false,
      msg: 'Token no es correcto'
    })
  }
}

const renewToken = async (req, res = response) => {
  const uid = req.uid

  // Generar el TOKEN - JWT
  const token = await generarJWT(uid)

  // Obtener el usuario del TOKEN
  const usuario = await Usuario.findById(uid)

  res.json({
    ok: true,
    token,
    usuario,
    menu: getMenu(usuario.role)
  })
}

module.exports = {
  login,
  googleSignIn,
  renewToken
}
