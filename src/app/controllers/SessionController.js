import * as Yup from 'yup'
import User from '../models/User'
import jwt from 'jsonwebtoken'
import authConfig from '../../config/auth'

class SessionController {
  async store(request, response) {
    const schema = Yup.object().shape({
      email: Yup.string().email().required(),
      password: Yup.string().required(),
    })
    // função criada para a resposta de email ou senha incorretos
    const incorrectEmailOrPassword = () => {
      return response
        .status(401)
        .json({ error: 'Make sure your email or password are correct!' })
    }

    // validação de email e usuário ao efetuar login
    if (!(await schema.isValid(request.body))) incorrectEmailOrPassword()

    const { email, password } = request.body

    // verificação da existência de um email igual ao informado na tela de login
    const user = await User.findOne({
      where: { email },
    })

    // verificação de email ao efetuar o login
    if (!user) incorrectEmailOrPassword()

    // verificação da senha ao efetuar o login
    if (!(await user.checkPassword(password))) incorrectEmailOrPassword()

    return response.json({
      id: user.id,
      email,
      name: user.name,
      admin: user.admin,
      token: jwt.sign({ id: user.id, name: user.name }, authConfig.secret, {
        expiresIn: authConfig.expiresIn,
      }),
    })
  }
}

export default new SessionController()
