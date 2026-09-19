/* Real C client against the Rust reference controller over a subprocess pipe. */
#include "openlock.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
static FILE *to_device,*from_device;
static struct {char name[32];uint8_t bytes[4096];size_t size;} fixtures[32];
static size_t fixture_count;
static size_t unhex(const char *text,uint8_t *out){size_t n=strcspn(text,"\r\n")/2;for(size_t i=0;i<n;i++){unsigned x=0;assert(sscanf(text+2*i,"%2x",&x)==1);out[i]=(uint8_t)x;}return n;}
static void local(const char *line){char reply[128];fprintf(to_device,"%s\n",line);fflush(to_device);assert(fgets(reply,sizeof reply,from_device));assert(strcmp(reply,"ok\n")==0);}
static size_t exchange(const uint8_t *input,size_t n,uint8_t *output){char reply[16384];for(size_t i=0;i<n;i++)fprintf(to_device,"%02x",input[i]);fprintf(to_device,"\n");fflush(to_device);assert(fgets(reply,sizeof reply,from_device));if(strncmp(reply,"error:",6)==0){fputs(reply,stderr);abort();}return unhex(reply,output);}
static uint64_t head(const uint8_t **p,unsigned major){uint8_t h=*(*p)++;assert(h>>5==major);unsigned ai=h&31;if(ai<24)return ai;unsigned count=ai==24?1:ai==25?2:ai==26?4:ai==27?8:0;assert(count);uint64_t n=0;while(count--)n=(n<<8)|*(*p)++;return n;}
static void skip(const uint8_t **p){unsigned major=**p>>5;if(**p==0xf6){(*p)++;return;}uint64_t n=head(p,major);if(major==2||major==3)*p+=n;else if(major==4)while(n--)skip(p);else assert(major==0);}
static openlock_session_t *connect_device(void){
    local("connect");uint8_t private_key[32],device_private[32],public_key[32],packet[4096],reply[4096],event[4096];memset(private_key,3,32);memset(device_private,4,32);
    assert(openlock_public_key(0,device_private,public_key)==0);openlock_session_t *session=NULL;assert(openlock_session_initiator(private_key,public_key,OPENLOCK_ALL_CAPABILITIES,&session)==0);
    size_t n=0;assert(openlock_session_start(session,NULL,0,&n)==-2);assert(openlock_session_start(session,packet,sizeof packet,&n)==0);
    size_t received=exchange(packet,n,reply);assert(openlock_session_receive(session,reply,received)==0);assert(openlock_session_take_event(session,event,sizeof event,&n)==0);const uint8_t *p=event;assert(head(&p,4)==4);assert(head(&p,0)==1);return session;
}
static void call(openlock_session_t *session,const char *name,unsigned reply_tag){
    size_t f=0;while(f<fixture_count&&strcmp(fixtures[f].name,name)!=0)f++;assert(f<fixture_count);
    uint8_t packet[4096],reply[4096],event[4096];size_t n=0;uint32_t id=0;
    assert(openlock_session_send(session,fixtures[f].bytes,fixtures[f].size,&id,NULL,0,&n)==-2);
    assert(openlock_session_send(session,fixtures[f].bytes,fixtures[f].size,&id,packet,sizeof packet,&n)==0);
    size_t received=exchange(packet,n,reply);assert(openlock_session_receive(session,reply,received)==0);
    assert(openlock_session_take_event(session,NULL,0,&n)==-2);assert(openlock_session_take_event(session,event,sizeof event,&n)==0);
    const uint8_t *p=event;assert(head(&p,4)==4);assert(head(&p,0)==3);assert(head(&p,0)==id);assert(*p++==0xf6);assert(head(&p,4)==3);(void)head(&p,0);assert(head(&p,0)==0);assert(head(&p,4)==2);assert(head(&p,0)==reply_tag);
    if(strcmp(name,"unlock")==0){assert(head(&p,4)==6);skip(&p);skip(&p);skip(&p);assert(head(&p,0)==1);}
    if(strcmp(name,"status")==0){assert(head(&p,4)==11);assert(head(&p,4)==2);assert(head(&p,0)==2);assert(head(&p,0)==1);}
}
int main(int argc,char **argv){
    assert(argc==2);FILE *file=fopen(argv[1],"r");assert(file);char name[32],text[8193];while(fscanf(file,"%31s %8192s",name,text)==2){assert(fixture_count<32);strcpy(fixtures[fixture_count].name,name);fixtures[fixture_count].size=unhex(text,fixtures[fixture_count].bytes);fixture_count++;}fclose(file);
    const char *path=getenv("OPENLOCK_SIMULATOR");assert(path);int in[2],out[2];assert(pipe(in)==0&&pipe(out)==0);pid_t child=fork();assert(child>=0);
    if(child==0){dup2(in[0],0);dup2(out[1],1);close(in[0]);close(in[1]);close(out[0]);close(out[1]);execl(path,path,(char*)NULL);_exit(127);}
    close(in[0]);close(out[1]);to_device=fdopen(in[1],"w");from_device=fdopen(out[0],"r");assert(to_device&&from_device);
    openlock_session_t *session=connect_device();call(session,"pairing",8);call(session,"claim",6);openlock_session_free(session);session=connect_device();
    call(session,"unlock",0);local("complete-unlock");call(session,"status",1);call(session,"lock",0);local("complete-lock");
    call(session,"config",0);call(session,"getconfig",3);call(session,"log",4);call(session,"begin",0);call(session,"chunk",0);call(session,"finish",0);call(session,"activate",0);local("confirm-boot");call(session,"firmware",5);
    call(session,"policy",0);call(session,"clock",0);call(session,"reboot",0);local("confirm-next");call(session,"reset",0);openlock_session_free(session);session=connect_device();call(session,"pairing",8);openlock_session_free(session);
    fprintf(to_device,"quit\n");fflush(to_device);fclose(to_device);fclose(from_device);int status;assert(waitpid(child,&status,0)==child);assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);puts("C ABI device lifecycle passed");return 0;
}
