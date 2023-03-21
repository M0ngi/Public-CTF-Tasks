// gcc main.c -o main -z relro -z now -fstack-protector

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct user{
    char uname[9];
    char birthday[40];
    char bio[360];
};

int changedUName = 0;

void verySecureFilter(char *s){
    for(int i=0; i<strlen(s); i++){
        if(s[i] == '%' || s[i] == '$'){
            s[i] = 0x20;
        }
    }
}

void readUserName(struct user* u){
    if(changedUName != 0){
        puts("You can set your username only once!");
        return;
    }

    read(0, u->uname, 9);
    u->uname[8] = 0;

    char welcome[256];
    sprintf(welcome, "Welcome! %s.\n", u->uname);
    
    printf(welcome);
    changedUName = 1;
}

void readBirthday(struct user* u){
    read(0, u->birthday, 40);

    verySecureFilter(u->birthday);
}

void readBio(struct user* u){
    read(0, u->bio, 360);

    verySecureFilter(u->bio);
}

void showInfo(struct user* u){
    printf("Username %s:\n", u->uname);
    printf(u->birthday);
    printf("Bio: %s", u->bio);
}

void menu(){
    puts("1. Set Username.");
    puts("2. Set Birth Date.");
    puts("3. Set Bio.");
    puts("4. Show Info.");
    puts("5. Disconnect.");
    printf(">> ");
}

int readChoice(){
    char x[2];
    read(0, x, 2);
    x[1] = '\0';
    return atoi(x);
}

void setup(){
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

int main(){
    setup();

    int choice;
    struct user u;

    do{
        menu();

        choice = readChoice();
        switch(choice){
            case 1:{
                readUserName(&u);
                break;
            }
            case 2:{
                readBirthday(&u);
                break;
            }
            case 3:{
                readBio(&u);
                break;
            }
            case 4:{
                showInfo(&u);
                break;
            }
        }
    }while(choice != 5);

    exit(0);
}