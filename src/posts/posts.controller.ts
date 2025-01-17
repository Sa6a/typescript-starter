import { Body, Controller, Delete, Get, Param, Patch, Post } from "@nestjs/common";
import PostsService from './posts.service';
import CreatePostDto from './dto/createPost.dto';
import UpdatePostDto from './dto/updatePost.dto'

@Controller('posts')
export default class PostsController {
    constructor(
        private readonly postsService: PostsService
    ) {}

    @Get()
    getAllPosts() {
    return this.postsService.getAllPosts();
    }

    @Get(':id')
    getPostById(@Param('id') id: string) {
        return this.postsService.getPostById(Number(id));
    }

    @Post()
    async createPost(@Body() post: CreatePostDto) {
        return this.postsService.createPost(post);
    }
    
    @Patch(':id')
    async replacePost(@Param('id') id: string, @Body() put: UpdatePostDto) {
        return this.postsService.updatePost(Number(id), put);
    }

    @Delete(':id')
    async deletePost(@Param('id') id: string) {
        return this.postsService.deletePost(Number(id));
    }
}



