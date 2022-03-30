//生成路由表
const router =require('express').Router()
// //引入密码加密
const bcrypt= require('bcryptjs')   //引入模块对加密的密码进行解密
// const { setEncode,constrast } = require('../util/encode')
//引入user mongodb模型
const user = require('../modules/user')
const jwt=require('jsonwebtoken')//导入加密字符
const expressJWT=require('express-jwt')//导入解密字符
//定义secret秘钥
const {secret}=require('../config/key')
//配置路由表
const sfyz=async(req,res,next)=>{
    //定义中间件具体的业务
    //解析表单数据的中间件
    // console.log(req.headers.authorization)
    //获取token
    //解析还原过程
// app.use(expressJWT({secret:secret}).unless({path:[/^\/api\//]}))//unless方法配置不需要访问权限的接口
//只要配置成功，expressjwt可以把解析的用户信息挂载到req.user上
    // const token= req.headers.authorization.split(' ')[1]
    // const tokenstr=expressJWT({secret:secret})
    // const id=token.split('.')[0]
    // const User=token.split('.')[1]
    // console.log(id,User)

    const tokenstr=req.headers.authorization.split(' ').pop()
    // console.log(jwt.verify(tokenstr,secret))
    const{_id ,username}=jwt.verify(tokenstr,secret)

    const User1 =await user.findById(_id) //从mongodb数据库中查找是否有相同_id的用户，有的话返回true
    if(!User1){ return res.status(422).send('用户错误')}
                                          //如果有相同_id再查username
        if(username !== User1.username)
        {
            res.status(422).send('用户名错误')
        }
        else {
            //用户存在,查看权限
            if (User1.isAdmin==='0')
            {res.status(409).send('没有权限')} //说明身份是用户
            else
             (User1.isAdmin==='1')
            {
                // res.send('Admin')
                next()
            }}
}




//获取用户列表
router.get('/user',sfyz,async(req,res) => {
    const list = await user.find({isAdmin: '0' }&&{isshow:'1'})
    res.send(list)
})
//分页操作
router.post('/user/page',sfyz,async(req,res) => {
    const list = await user.find({isAdmin: '0' }&&{isshow:'1'})
    // console.log(req.body.pagenum)
    const arry10=list.slice(0+10*(req.body.pagenum-1),10+10*(req.body.pagenum-1))
    res.send(arry10)
})
//重置用户
router.get('/user/reset',sfyz,async(req,res) => {
    const reqdel= await user.updateMany({isAdmin: '0' }&&{isshow:'0'},{isshow:'1'},function(err,raw){
        if(err){ console.log(err)}
        // console.log('The raw response from Mongo was',raw)
        res.send('恢复成功')
        // console.log(1)
    })
})
//更改用户名
router.post('/user/change',sfyz,async(req,res) => {
    // console.log(req.body)
    const User= await user.findOne({ name: req.body.username})
    if(User){ return res.status(409).send('该用户名已存在')}   //判断用户名是否存在
    const reqchange= await user.updateOne({username: req.body.first.username},{name: req.body.username},function(err,raw){
        if(err){ console.log(err)}
        // console.log('The raw response from Mongo was',raw)
        res.send('修改成功')
        // console.log(1)
    })
})
//删除用户
router.post('/user/del',async(req,res)=>{
    // console.log(req)
    const reqdel= await user.updateOne({username: req.body.username},{isshow:'0'},function(err,raw){
        if(err){ console.log(err)}
        // console.log('The raw response from Mongo was',raw)
        res.send('删除成功')
    })
    
    
})
//注册
router.post('/register',async(req,res) => {
    const User= await user.findOne({ username: req.body.username})
    if(User){ return res.status(409).send('该用户已存在')}   //判断注册的用户是否存在
    // //密码加密
    // req.body.password=setEncode(req.body.password,salt)
    // req.body
    const newUser = await user(req.body).save()
    res.send(newUser)
})
//登录
router.post('/login',async(req,res) => {
    const User= await user.findOne({ username: req.body.username})
    if(!User){ return res.status(422).send('该用户不存在')} //判断登录的用户是否存在
    // if(req.body.password !== User.password){return res.status(422).send('密码错误')} //判断密码是否正确
    // else{ return res.send('token')}
    // //解密
    let ispassword = bcrypt.compareSync(req.body.password,User.password)  //将数据库中的密码进行解密和发送的密码进行配对
    if(!ispassword){return res.status(422).send('密码错误')}
    // res.send(user)
    // const token =User._id+'.'+User.username     //User对象从mongodb  user modoule中获取
    // res.send(token)
    const tokenstr=jwt.sign({username:User.username,  _id:User._id},secret,{expiresIn:'24h'})
    // console.log(tokenstr)
    res.send({
        token: tokenstr
})
})

//验证
// router.get('/verify',async(req,res)=>{
//     console.log(req.headers.authorization)
//     //获取token
//     const token= req.headers.authorization.split(' ')[1]
//     const id=token.split('.')[0]
//     const User=token.split('.')[1]
//     console.log(id,User)
//     const User1 =await user.findById(id) //从mongodb数据库中查找是否有相同_id的用户，有的话返回true
//     if(!User1){ return res.status(422).send('用户错误')}
//                                           //如果有相同_id再查username
//         if(User !== User1.username)
//         {
//             res.status(422).send('用户名错误')
//         }
//         else {
//             //用户存在,查看权限
//             if (User1.isAdmin==='0')
//             {res.status(409).send('没有权限')} //说明身份是用户
//             else
//              (User1.isAdmin==='1')
//             {
//                 res.send('Admin')
//             }}

// })将其封装为sfyz中间件
//导出路由表
module.exports =router