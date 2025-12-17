#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<stdint.h>

typedef struct player {
    char name[32];
    uint8_t class;
} player_t;

player_t * list[0x10];
//classes available
//magician-1
//swordsman-2
//theif-3
//D3rlord3-0


void menu(){
    puts("---MUD---");
    puts("1.Make a new Character");
    puts("2.Defeat the Yellow King");
    puts("3.Return");
    printf(">>");
}

void make_char(){
    
    //initialize
    int idx =0;
    puts("enter index:");
    scanf("%d",&idx);
    if(idx<0 || idx >=0x10){
        puts("wrong index");
        return;
    }

    player_t *p = malloc(sizeof(player_t));
    
    puts("Enter the class");
    printf("1.magician\n2.swordsman\n3.thief\n>>");
    scanf("%hhu",&p->class);
    //check class
    if(p->class < 1 || p->class >= 4){ 
        if(p->class == 0x00 ){
            puts("You aren't D3rdlord3");
            free(p);
        }
        else{
            puts("Wrong class");
            free(p);
        }
        return;
    }
    //off-by-one read name, can make class = Null
    printf("Enter the name for character\n>>");
    p->name[read(0,p->name,32)] = 0x00; 
    list[idx]=p;
}
int count_char(char *str,int ascii_char ,int num) {
    char arr[256] = {0};
    for(int i=0;i<strlen(str);i++)
        arr[str[i]]++;
    if (arr[ascii_char] > num)
        return 1;
    else return 0;
}
void action(){
    
    int idx;
    puts("enter index:");
    scanf("%d",&idx);
    if(idx<0 || idx >=0x10){
        puts("wrong index");
        return;
    }
    player_t * p = list[idx];
    printf("You chose %s \n",p->name);
    char msg[64];    
    switch (p->class){
        case 0x00:
            printf("You may leave a message about your encounter and leave..\n");
            read(0,msg,48);
            //detect no of %, no more than 13
            //0x25 is %n no more than 13
            if(count_char(msg,0x25,13)) {
                puts("No one can handle that much knowledge..");
                return;
            }
            puts("The message left for other adventurers..");
            printf(msg); //fmt string
            break;
        case 1:
            printf("You have lost\n");
            list[idx]=NULL;
            free(p);
            break;
        case 2:
            printf("You have lost\n");
            list[idx]=NULL;
            free(p);
            break;
        case 3:
            printf("You have lost\n");
            list[idx]=NULL;
            free(p);
            break;
    }
}
int main(){
    setbuf(stdout,NULL);
    setbuf(stdin,NULL);
    setbuf(stderr,NULL);
    int choice;
    while(1){
        menu();
        scanf("%d",&choice);
        switch(choice) {
            case 1:
                make_char();
                break;
            case 2:
                action();
                break;
            case 3:
                exit(0);
            default:
                puts("wrong option");
        }
    }  
}
