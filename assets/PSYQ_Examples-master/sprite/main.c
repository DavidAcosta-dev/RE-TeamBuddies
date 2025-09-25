/*
 * Written By: John Convertino
 * 
 * Sprite example, in a world.
 * 
 * Move square with D-Pad, press X to change color.
 * 
 */

#include <engine.h>
//define world size and number of objects
#define WORLD_HEIGHT 	480
#define WORLD_WIDTH  	640
#define OBJECTS		10

//create objects
void createGameObjects(struct s_environment *p_env);
//move player sprite
void movSprite(struct s_environment *p_env);
//move enemy sprite to chase
void movEnemy(struct s_environment *p_env);
//rotate squares in world
void rotSqrs(struct s_environment *p_env);

int main() 
{
  int index;
  
  char *p_title = "Sprite Example\nLoaded From CD\nBITMAP to PSX DATA CONV";
  struct s_environment environment;

  initEnv(&environment, OBJECTS);
  
  environment.envMessage.p_data = (int *)&environment.gamePad.one;
  environment.envMessage.p_message = NULL;
  environment.envMessage.p_title = p_title;
  
  createGameObjects(&environment);
  
  populateOT(&environment);
  
  populateTextures(&environment);

  for(;;)
  {
    display(&environment);
    movSprite(&environment);
    movEnemy(&environment);
    rotSqrs(&environment);
    
    //translate all primitives after updating vectors
    for(index = 0; index < environment.otSize; index++)
    {
      transPrim(environment.p_primParam[index], &environment);
    }
      
    updatePrim(&environment);
  }

  return 0;
}

//create game objects
void createGameObjects(struct s_environment *p_env)
{
  int index;
  int buffIndex;
  
  //define and get info of each object
  p_env->p_primParam[0] = getObjects("\\SAND.XML;1");
  p_env->p_primParam[1] = getObjects("\\SPRITE.XML;1");
  p_env->p_primParam[2] = getObjects("\\ESPRITE.XML;1");
  p_env->p_primParam[3] = getObjects("\\SQ1.XML;1");
  p_env->p_primParam[4] = getObjects("\\SQ2.XML;1");
  p_env->p_primParam[5] = getObjects("\\SQ3.XML;1");
  p_env->p_primParam[6] = getObjects("\\SQ4.XML;1");
  p_env->p_primParam[7] = getObjects("\\SQ5.XML;1");
  p_env->p_primParam[8] = getObjects("\\SQ6.XML;1");
  p_env->p_primParam[9] = getObjects("\\SQ7.XML;1");
  
  for(index = 0; index < p_env->otSize; index++)
  {
    if(p_env->p_primParam[index] != NULL)
    {
      //for both buffers create the primitive for the object
      for(buffIndex = 0; buffIndex < DOUBLE_BUF; buffIndex++)
      {
	//based on the type, allocate memory for the primitive in the buffer
	switch(p_env->p_primParam[index]->type)
	{
	  case TYPE_F4:
	    p_env->buffer[buffIndex].p_primitive[index].data = calloc(1, sizeof(POLY_F4));
	    break;
	  case TYPE_FT4:
	    p_env->buffer[buffIndex].p_primitive[index].data = calloc(1, sizeof(POLY_FT4));
	    break;
	  case TYPE_SPRITE:
	    p_env->buffer[buffIndex].p_primitive[index].data = calloc(1, sizeof(SPRT));
	    break;
	  default:
	    break;
	}
      }
    }
  } 
}

//animate sprites, allows us to move to the correct place in a sprite table, and have a common timing between frames
void animate(struct s_environment *p_env, int *op_prevTime, int sprite, int yoffset)
{
  if(*op_prevTime == 0 || ((VSync(-1) - *op_prevTime) >= 8))
  {
    *op_prevTime = VSync(-1);
    
    p_env->p_primParam[sprite]->p_texture->vertex0.vy = yoffset;
    p_env->p_primParam[sprite]->p_texture->vertex0.vx = (p_env->p_primParam[sprite]->p_texture->vertex0.vx + 64) % 256;
  }
}

//move player character
void movSprite(struct s_environment *p_env)
{ 
  static int prevTime = 0;
  static int prevAnimTime = 0;
  int movAmount = 1;
  
  if(p_env->gamePad.one.fourth.bit.triangle == 0)
  {
    movAmount = 2;
    prevAnimTime--;
  }
   
  if(p_env->gamePad.one.fourth.bit.ex == 0)
  {
    if(prevTime == 0 || ((VSync(-1) - prevTime) > 60))
    {
      p_env->p_primParam[1]->color0.r = rand() % 256;
      p_env->p_primParam[1]->color0.g = rand() % 256;
      p_env->p_primParam[1]->color0.b = rand() % 256;
      prevTime = VSync(-1);
    }
  }
  //same for all input presses, if the button is pressed
  else if(p_env->gamePad.one.third.bit.up == 0)
  {
    //and we have not hit a boundry
    if(p_env->p_primParam[1]->transCoor.vy > 0)
    {
      //update character move amount, and animate that movement
      p_env->p_primParam[1]->transCoor.vy -= movAmount;
      animate(p_env, &prevAnimTime, 1, 192);
    }
    else
    {
      //if we are not moving, set to standing frame
      p_env->p_primParam[1]->p_texture->vertex0.vx = 0;
    }
    
    //move screen based on player position
    if((p_env->screenCoor.vy > 0) && (p_env->p_primParam[1]->transCoor.vy <= (WORLD_HEIGHT - SCREEN_HEIGHT/2 - 32)))
    {
      p_env->screenCoor.vy -= movAmount;
    }

  }
  //see above
  else if(p_env->gamePad.one.third.bit.right == 0)
  {
    if((p_env->p_primParam[1]->transCoor.vx + p_env->p_primParam[1]->dimensions.w) < WORLD_WIDTH)
    {
      p_env->p_primParam[1]->transCoor.vx += movAmount;
      animate(p_env, &prevAnimTime, 1, 128);
    }
    else
    {
      p_env->p_primParam[1]->p_texture->vertex0.vx = 0;
    }
    
    if(((p_env->screenCoor.vx + SCREEN_WIDTH) < WORLD_WIDTH) && (p_env->p_primParam[1]->transCoor.vx >= (SCREEN_WIDTH/2 - 32)))
    {
      p_env->screenCoor.vx += movAmount;
    }
  }
  //see above
  else if(p_env->gamePad.one.third.bit.down == 0)
  {
    if((p_env->p_primParam[1]->transCoor.vy + p_env->p_primParam[1]->dimensions.h) < WORLD_HEIGHT)
    {
      p_env->p_primParam[1]->transCoor.vy += movAmount;
      animate(p_env, &prevAnimTime, 1, 0);
    }
    else
    {
      p_env->p_primParam[1]->p_texture->vertex0.vx = 0;
    }
    
    if(((p_env->screenCoor.vy + SCREEN_HEIGHT) < WORLD_HEIGHT) && (p_env->p_primParam[1]->transCoor.vy >= (SCREEN_HEIGHT/2 - 32)))
    {
      p_env->screenCoor.vy += movAmount;
    }
  }
  //see above
  else if(p_env->gamePad.one.third.bit.left == 0)
  {
    if(p_env->p_primParam[1]->transCoor.vx > 0)
    {
      p_env->p_primParam[1]->transCoor.vx -= movAmount;
      animate(p_env, &prevAnimTime, 1, 64);
    }
    else
    {
      p_env->p_primParam[1]->p_texture->vertex0.vx = 0;
    }
    
    if((p_env->screenCoor.vx > 0) && (p_env->p_primParam[1]->transCoor.vx <= (WORLD_WIDTH - SCREEN_WIDTH/2 - 32)))
    {
      p_env->screenCoor.vx -= movAmount;
    }
  }
  //if nothing is pressed, set to standing frame in sprite table
  else
  {
    p_env->p_primParam[1]->p_texture->vertex0.vx = 0;
  }
}

//move enemy sprite
void movEnemy(struct s_environment *p_env)
{ 
  static int prevAnimTime = 0;
  
  //if we're close, stop moving
  if((abs(p_env->p_primParam[1]->transCoor.vy - p_env->p_primParam[0]->transCoor.vy) + 25 < 50) && (abs(p_env->p_primParam[1]->transCoor.vx - p_env->p_primParam[0]->transCoor.vx) + 25 < 50))
  {
    p_env->p_primParam[2]->p_texture->vertex0.vx = 0;
    return;
  }

  //keep moving verticaly towards the player
  if(p_env->p_primParam[1]->transCoor.vy > p_env->p_primParam[2]->transCoor.vy)
  {
    if((p_env->p_primParam[2]->transCoor.vy + p_env->p_primParam[2]->dimensions.h) < SCREEN_HEIGHT)
    {
      p_env->p_primParam[2]->transCoor.vy += 1;
      animate(p_env, &prevAnimTime, 2, 0);
    }
    else
    {
      p_env->p_primParam[2]->p_texture->vertex0.vx = 0;
    }
  }
  //keep moving verticaly towards the player
  else if(p_env->p_primParam[1]->transCoor.vy < p_env->p_primParam[2]->transCoor.vy)
  {
    if(p_env->p_primParam[2]->transCoor.vy > 0)
    {
      p_env->p_primParam[2]->transCoor.vy -= 1;
      animate(p_env, &prevAnimTime, 2, 192);
    }
    else
    {
      p_env->p_primParam[2]->p_texture->vertex0.vx = 0;
    }
  } 
  //keep moving horizontaly towards the player
  else if(p_env->p_primParam[1]->transCoor.vx > p_env->p_primParam[2]->transCoor.vx)
  {
    if((p_env->p_primParam[2]->transCoor.vx + p_env->p_primParam[2]->dimensions.w) < SCREEN_WIDTH)
    {
      p_env->p_primParam[2]->transCoor.vx += 1;
      animate(p_env, &prevAnimTime, 2, 128);
    }
    else
    {
      p_env->p_primParam[2]->p_texture->vertex0.vx = 0;
    }
  }
  //keep moving horizontaly towards the player
  else if(p_env->p_primParam[1]->transCoor.vx < p_env->p_primParam[2]->transCoor.vx)
  {
    if(p_env->p_primParam[2]->transCoor.vx > 0)
    {
      p_env->p_primParam[2]->transCoor.vx -= 1;
      animate(p_env, &prevAnimTime, 2, 64);
    }
    else
    {
      p_env->p_primParam[2]->p_texture->vertex0.vx = 0;
    }
  }
  else
  {
    p_env->p_primParam[2]->p_texture->vertex0.vx = 0;
  }
}

//rotate any primitve of the type F4, since those are the only
//squares in are world.
void rotSqrs(struct s_environment *p_env)
{
  int index;
  static int prevTime = 0;
  
  if(prevTime == 0 || ((VSync(-1) - prevTime) > 5))
  {
    for(index = 0; index < p_env->otSize; index++)
    {
      if(p_env->p_primParam[index]->type == TYPE_F4)
      {
	p_env->p_primParam[index]->rotCoor.vz += 128;
      }
    }
    
    prevTime = VSync(-1);
  }
}