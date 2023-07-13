/* eslint-disable no-unused-vars */
/* eslint-disable no-undef */
import { verify } from 'jsonwebtoken'

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

const validarAdminRole = (req, res, next) => {
  const uid = req.uid
  try {
    console.log(uid)
  } catch (error) {
    console.log(error)
    return res.status(500).json({
      ok: false,
      msg: 'Hable con el administrador',
    })
  }
}

export default {
  validarJWT,
  validarAdminRole,
}
