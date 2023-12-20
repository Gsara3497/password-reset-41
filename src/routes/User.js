import express from 'express'
import UserController from '../controller/User.js'
import Auth from '../common/auth.js'

const router = express.Router()

router.get('/',UserController.getEmail)
router.post('/signup',UserController.postEmail)
router.post('/login',UserController.loginEmail)
router.get('/data',Auth.validate,UserController.verifyToken)
router.post('/reset-password',UserController.resetPassword)
router.post('/getreset-password/:OTP/:password',UserController.getResetPassword)

export default router