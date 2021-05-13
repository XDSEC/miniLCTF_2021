#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<unistd.h>
void welcome(){
	printf("CDCQ wants to make a game with you!\n\n");
	printf("There are some cats in XDU. Now cdcq and you will take turns in catching these cats.\n\n");
	printf("CDCQ will tell you the number of cats, and he will catch firstly. Then is your turn.\n\n");
	printf("What's more, the number of cats couched in every turn must be not greater than the\n\
last turn, and must be greater than 1.\n\n");
	printf("The man who catches the last cat in XDU will win the game, and cdcq will not catch\n\
all cats at the first round.\n\n");
	printf("Small cat tells you quietly: in order to make sure you will win, cdcq will not choose\n\
the best number at the first round.\n\n");
	printf("If this problem is toooooo difficult for you, you can input help to get some hints.\n\n");
	printf("Let's go!\n\n");
}
int lowbit(int x){  return x&-x;}
int cow_count=0;
int check(char *s){
	if(s[0]=='h' && s[1]=='e' && s[2]=='l' && s[3] == 'p'){
		if(cow_count==1){
			printf(R"( ________________________
< Learn from your enemy. >
 ------------------------
   \
    \

     |\_/|
     |o o|__
     --w--__\
     C_C_(___)
)");
		}
		else if(cow_count==2){
		    printf(R"( ___________________
< Watch your enemy. >
 -------------------
   \
    \

     |\_/|
     |o o|__
     --w--__\
     C_C_(___)
)");
		}
		else{
			printf(R"( ________________________________
/ What doesnt kill you makes you \
\ stronger.                      /
 --------------------------------
   \
    \

     |\_/|
     |o o|__
     --w--__\
     C_C_(___)
)");
		}
		cow_count=(cow_count+1)%3;
	}
	for(int i=0;s[i]!=0 && s[i]!='\n' && s[i]!='\r';++i){
		if(s[i]<'0' || s[i]>'9')  return 0;
	}
	return 1;
}
int toint(char *s){
	int number=0;
	for(int i=0;s[i]!=0 && s[i]!='\n' && s[i]!='\r';++i)
		number=number*10+s[i]-'0';
	return number;
}
int main(){
	srand((unsigned)time(NULL));
	const char *flag= getenv("FLAG");
	welcome();
	int cats=rand()%100+100;
	cats>>=5;
	cats<<=5;
	cats+=16+(rand()%16);
	printf("The number of cats in XDU is %d.\n",cats);
	int last=-1;
	for(;;){
		if(last==-1){
			last=32+(cats%4);
		}
		else if(lowbit(cats)>last){
			/*
			int temp=rand()%((last>cats ? cats : last)/2+1)+1;
			if((cats-temp)%2==1){
				if(temp>1)  temp--;
				else if(temp+1<=last)  temp++;
			}
			*/
			if(last!=1){
				last=rand()%((last>cats ? cats-1: last-1)/2+1)+2;
			}
		}
		else{
			last=lowbit(cats);
		}
		printf("CDCQ catches %d cats!\n", last);
		cats-=last;
		printf("The number of cats in XDU is %d.\n",cats);
		if(cats==0){
			printf("CDCQ win the game >w<\n");
			return 0;
		}
		for(;;){
			printf("The number of cats you will catch is:");
			fflush(stdout);
			int number;
			char s[20];
			read(0,s,10);
			if(check(s)==0){
				continue;
			}
			number=toint(s);
			if(number>last){
				printf("You must catch cats not greater than %d >n<\n",last);
				continue;
			}
			if(number<=0){
				printf("You must catch cats more than one >n<\n");
				continue;
			}
			if(number>cats){
				printf("There are not too much cats >n<\n");
				continue;
			}
			cats-=number;
			last=number;
			printf("The number of cats in XDU is %d.\n",cats);
			break;
		}
		if(cats==0){
			printf("You win!\n");
			printf("%s\n",flag);
			return 0;
		}
	}
	return 0;
}


