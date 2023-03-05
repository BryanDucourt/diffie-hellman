//
// Created by bryandu on 22-6-26.
//
#include "DH.h"
#include "iostream"

unsigned int GenerateRandomOdd(){
    time_t t;//c++时间类型
    unsigned int RandomNumber;//记录随机数
    do{

        RandomNumber=(rand()<<17)|(rand()<<3)|(rand());
        //cout<<RandomNumber<<endl;
    }while(RandomNumber%2==0||RandomNumber<100000000);
    //返回
    return RandomNumber;
}

size_t Mod(size_t a, size_t b, size_t c) {                       //求a的b次方 模c
    if(b == 0) return 1;                                //递归边界：0次幂=1
    if(b % 2 == 1) return a * Mod(a*a % c, b/2, c) % c; //b是奇数时
    else return Mod(a*a % c, b/2, c) % c;               //b是偶数时
}

size_t RepeatMod(size_t base, size_t n, size_t mod){
    size_t a = 1;
    while(n){
        if(n&1){
            a=(a*base)%mod;
        }
        base=(base*base)%mod;
        n=n>>1;
    }
    return a;
}
bool RobinMiller(size_t n,size_t k){
    int s=0;
    int temp=n-1;

    //将n-1表示为(2^s)*t
    while ((temp&0x1)==0&&temp){
        temp=temp>>1;
        s++;
    }
    size_t t = temp;

    //判断k轮误判概率不大于(1/4)^k
    while(k--){
        size_t b = rand()%(n-2)+2; //生成一个b(2≤a ≤n-2)

//        size_t y = RepeatMod(b,t,n);
        size_t y = Mod(b,t,n);
        if (y == 1 || y == (n-1))
            return true;
        for(int j = 1; j<=(s-1) && y != (n-1); ++j){
//            y = RepeatMod(y,2,n);
            y = Mod(y,2,n);
            if (y == 1)
                return false;
        }
        if (y != (n-1))
            return false;
    }
    return true;
}
tuple<unsigned int, unsigned int> DiffieHellman::GenerateExKey() {
    size_t k = 80;
    bool flag = false;
    unsigned int odd;
    while (!flag){
        odd = GenerateRandomOdd();

        flag = RobinMiller(odd,k);
    }
    private_key = odd;
    flag = false;
    while (!flag){
        odd = GenerateRandomOdd();
        flag = RobinMiller(odd,k);
    }
    mod_p = odd;
    generator = 2;
//    exchange_key = RepeatMod(2,private_key,mod_p);
    exchange_key = Mod(2,private_key,mod_p);
    return {exchange_key,mod_p};
}

unsigned int DiffieHellman::GenerateExKey(unsigned int gen, unsigned int mod) {
    size_t k = 80;
    bool flag = false;
    unsigned int odd;
    while (!flag){
        odd = GenerateRandomOdd();

        flag = RobinMiller(odd,k);
    }
    private_key = odd;
    mod_p = mod;
    generator = gen;
//    exchange_key = RepeatMod(generator,private_key,mod_p);
    exchange_key = Mod(generator,private_key,mod_p);
    return exchange_key;
}

void DiffieHellman::GeneratePubKey() {
//    public_key = RepeatMod(recv_key,private_key,mod_p);
    public_key = Mod(recv_key,private_key,mod_p);
}

void DiffieHellman::UpdateRecvKey(unsigned int key) {
    recv_key = key;
}
