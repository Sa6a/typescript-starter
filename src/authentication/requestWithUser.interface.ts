import { Request } from 'express';
import User from "src/users/user.entity";

interface RequestWithUser extends Request {
    user: User;
}

export default RequestWithUser;