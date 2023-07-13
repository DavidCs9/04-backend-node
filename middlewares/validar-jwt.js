const { verify } = require('jsonwebtoken')
const Usuario = require('../models/usuario')

const validarJWT = (req, res, next) => {
  // Leer el Token
  const token = req.header('x-token')

  if (!token) {
    return res.status(401).json({
      ok: false,
      msg: 'No hay token en la petición',
    })
  }

  try {
    const { uid } = verify(token, process.env.JWT_SECRET)
    req.uid = uid

    next()
  } catch (error) {
    return res.status(401).json({
      ok: false,
      msg: 'Token no válido',
    })
  }
}

const validarAdminRole = async (req, res, next) => {
  const uid = req.uid
  try {
    const usuarioDB = await Usuario.findById(uid)
    if (!usuarioDB) {
      return res.status(404).json({
        ok: false,
        msg: 'Usuario no encontrado',
      })
    }
    if (usuarioDB.role !== 'ADMIN_ROLE') {
      return res.status(401).json({
        ok: false,
        msg: 'Acceso denegado',
      })
    }
    next()
  } catch (error) {
    console.log(error)
    return res.status(500).json({
      ok: false,
      msg: 'Hable con el administrador',
    })
  }
}

const validarAdminRoleOMismoUsuario = async (req, res, next) => {
  const uid = req.uid
  const id = req.params.id
  try {
    const usuarioDB = await Usuario.findById(uid)
    if (!usuarioDB) {
      return res.status(404).json({
        ok: false,
        msg: 'Usuario no encontrado',
      })
    }
    if (usuarioDB.role !== 'ADMIN_ROLE' && uid !== id) {
      return res.status(401).json({
        ok: false,
        msg: 'Acceso denegado',
      })
    }
    next()
  } catch (error) {
    console.log(error)
    return res.status(500).json({
      ok: false,
      msg: 'Hable con el administrador',
    })
  }
}

module.exports = {
  validarJWT,
  validarAdminRole,
  validarAdminRoleOMismoUsuario,
}
