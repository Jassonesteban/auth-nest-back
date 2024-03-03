import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto } from './dto/register.dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService
  ) { }



  async create(createUserDto: CreateUserDto): Promise<User> {

    try {
      //encriptar las contraseñas
      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel({ password: bcryptjs.hashSync(password, 10), ...userData });

      await newUser.save();

      const { password: _, ...user } = newUser.toJSON();

      return user;
    } catch (error) {

      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} ya existe!`);
      }

      throw new InternalServerErrorException('Algo malo ha pasado en el servidor');
    }
  }

  async register(registerDTO: RegisterUserDto):Promise<LoginResponse>{
    const user = await this.create(registerDTO);

    return {
      user: user,
      token: this.getJWTtoken({id: user._id})
    }
  }

  async login(loginDTO: LoginDto):Promise<LoginResponse> {

    const { email, password } = loginDTO;

    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new UnauthorizedException('Credenciales no encontradas');
    }

    if (!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Credenciales no encontradas');
    }

    const {password:_, ...rest} = user.toJSON();

    return {
      user: rest,
      token: this.getJWTtoken({id: user.id}),
    };

  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id: string){
    const user = await  this.userModel.findById(id);
    const {password, ...rest} = user.toJSON();

    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJWTtoken(payload: JwtPayload){
    const token = this.jwtService.sign(payload);
    return token;
  }
}
