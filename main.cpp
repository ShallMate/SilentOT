
#include <libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtSender.h>
#include <iomanip>
#include <cryptoTools/Network/IOService.h>
#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <libOTe/Tools/LDPC/LdpcImpulseDist.h>
#include <libOTe/Tools/LDPC/Util.h>
#include <coproto/Socket/BufferingSocket.h>
#include <libOTe_Tests/Common.h>
#include <cryptoTools/Common/TestCollection.h>

using namespace osuCrypto;
using namespace std;
using namespace tests_libOTe;

enum class Role{
        Sender,
        Receiver
};

namespace osuCrypto{

using ProtocolFunc = std::function<void(Role, int, int, std::string, std::string, CLP&)>;



inline bool runIf(ProtocolFunc protocol, CLP & cmd, std::vector<std::string> tag,
                      std::vector<std::string> tag2 = std::vector<std::string>())
    {
        auto n = cmd.isSet("nn")
            ? (1 << cmd.get<int>("nn"))
            : cmd.getOr("n", 0);

        auto t = cmd.getOr("t", 1);
        auto ip = cmd.getOr<std::string>("ip", "localhost:1212");

        if (!cmd.isSet(tag))
            return false;

        if (!tag2.empty() && !cmd.isSet(tag2))
            return false;

        if (cmd.hasValue("r"))
        {
            auto role = cmd.get<int>("r") ? Role::Sender : Role::Receiver;
            protocol(role, n, t, ip, tag.back(), cmd);
        }
        else
        {
            auto thrd = std::thread([&] {
                try { protocol(Role::Sender, n, t, ip, tag.back(), cmd); }
                catch (std::exception& e)
                {
                    lout << e.what() << std::endl;
                }
                });

            try { protocol(Role::Receiver, n, t, ip, tag.back(), cmd); }
            catch (std::exception& e)
            {
                lout << e.what() << std::endl;
            }
            thrd.join();
        }

        return true;
    }

}

static const std::vector<std::string>
Silent{ "s", "Silent" };

void Silent_example(Role role, u64 numOTs, u64 numThreads, std::string ip, std::string tag, CLP& cmd)
    {
        if (numOTs == 0)
            numOTs = 1 << 20;

        // get up the networking
        auto chl = cp::asioConnect(ip, role == Role::Sender);


        PRNG prng(sysRandomSeed());

        bool fakeBase = cmd.isSet("fakeBase");
        u64 trials = cmd.getOr("trials", 1);
        auto malicious = cmd.isSet("mal") ? SilentSecType::Malicious : SilentSecType::SemiHonest;
        auto multType = cmd.isSet("silver") ? MultType::slv5 : MultType::QuasiCyclic;

        std::vector<SilentBaseType> types;
        if (cmd.isSet("base"))
            types.push_back(SilentBaseType::Base);
        else 
            types.push_back(SilentBaseType::BaseExtend);

        macoro::thread_pool threadPool;
        auto work = threadPool.make_work();
        if (numThreads > 1)
            threadPool.create_threads(numThreads);

        for (auto type : types)
        {
            for (u64 tt = 0; tt < trials; ++tt)
            {
                Timer timer;
                auto start = timer.setTimePoint("start");
                if (role == Role::Sender)
                {
                    SilentOtExtSender sender;

                    // optionally request the LPN encoding matrix.
                    sender.mMultType = multType;

                    // optionally configure the sender. default is semi honest security.
                    sender.configure(numOTs, 2, numThreads, malicious);

                    if (fakeBase)
                    {
                        auto nn = sender.baseOtCount();
                        BitVector bits(nn);
                        bits.randomize(prng);
                        std::vector<std::array<block, 2>> baseSendMsgs(bits.size());
                        std::vector<block> baseRecvMsgs(bits.size());

                        auto commonPrng = PRNG(ZeroBlock);
                        commonPrng.get(baseSendMsgs.data(), baseSendMsgs.size());
                        for (u64 i = 0; i < bits.size(); ++i)
                            baseRecvMsgs[i] = baseSendMsgs[i][bits[i]];

                        sender.setBaseOts(baseRecvMsgs, bits);
                    }
                    else
                    {
                        // optional. You can request that the base ot are generated either
                        // using just base OTs (few rounds, more computation) or 128 base OTs and then extend those. 
                        // The default is the latter, base + extension.
                        cp::sync_wait(sender.genSilentBaseOts(prng, chl, type == SilentBaseType::BaseExtend));
                    }

                    std::vector<std::array<block, 2>> messages(numOTs);

                    // create the protocol object.
                    auto protocol = sender.silentSend(messages, prng, chl);

                    // run the protocol
                    if (numThreads <= 1)
                        cp::sync_wait(protocol);
                    else
                        // launch the protocol on the thread pool.
                        cp::sync_wait(std::move(protocol) | macoro::start_on(threadPool));

                    // messages has been populated with random OT messages.
                    // See the header for other options.
                }
                else
                {

                    SilentOtExtReceiver recver;

                    // optionally request the LPN encoding matrix.
                    recver.mMultType = multType;

                    // configure the sender. optional for semi honest security...
                    recver.configure(numOTs, 2, numThreads, malicious);

                    if (fakeBase)
                    {
                        auto nn = recver.baseOtCount();
                        BitVector bits(nn);
                        bits.randomize(prng);
                        std::vector<std::array<block, 2>> baseSendMsgs(bits.size());
                        std::vector<block> baseRecvMsgs(bits.size());

                        auto commonPrng = PRNG(ZeroBlock);
                        commonPrng.get(baseSendMsgs.data(), baseSendMsgs.size());
                        for (u64 i = 0; i < bits.size(); ++i)
                            baseRecvMsgs[i] = baseSendMsgs[i][bits[i]];

                        recver.setBaseOts(baseSendMsgs);
                    }
                    else
                    {
                        // optional. You can request that the base ot are generated either
                        // using just base OTs (few rounds, more computation) or 128 base OTs and then extend those. 
                        // The default is the latter, base + extension.
                        cp::sync_wait(recver.genSilentBaseOts(prng, chl, type == SilentBaseType::BaseExtend));
                    }

                    std::vector<block> messages(numOTs);
                    BitVector choices(numOTs);

                    // create the protocol object.
                    auto protocol = recver.silentReceive(choices, messages, prng, chl);

                    // run the protocol
                    if (numThreads <= 1)
                        cp::sync_wait(protocol);
                    else
                        // launch the protocol on the thread pool.
                        cp::sync_wait(std::move(protocol) | macoro::start_on(threadPool));

                    // choices, messages has been populated with random OT messages.
                    // messages[i] = sender.message[i][choices[i]]
                    // See the header for other options.
                }
                auto end = timer.setTimePoint("end");
                auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

                u64 com = chl.bytesReceived() + chl.bytesSent();

                if (role == Role::Sender)
                {
                    std::string typeStr = type == SilentBaseType::Base ? "b " : "be ";
                    lout << tag <<
                        " n:" << Color::Green << std::setw(6) << std::setfill(' ') << numOTs << Color::Default <<
                        " type: " << Color::Green << typeStr << Color::Default <<
                        "   ||   " << Color::Green <<
                        std::setw(6) << std::setfill(' ') << milli << " ms   " <<
                        std::setw(6) << std::setfill(' ') << com << " bytes" << std::endl << Color::Default;

                    if (cmd.getOr("v", 0) > 1)
                        lout << gTimer << std::endl;
                }

                if (cmd.isSet("v"))
                {
                    if (role == Role::Sender)
                        lout << " **** sender ****\n" << timer << std::endl;

                    if (role == Role::Receiver)
                        lout << " **** receiver ****\n" << timer << std::endl;
                }
            }
    }
}

void fakeBase(u64 n,u64 s,u64 threads,PRNG& prng,SilentOtExtReceiver& recver, SilentOtExtSender& sender){
        sender.configure(n, s, threads);
        //auto count = sender.silentBaseOtCount();
        auto const1 = sender.mGen.baseOtCount();
        auto const2 = sender.mGapOts.size();
        auto const3 = (sender.mMalType == SilentSecType::Malicious) * 128;
        cout<<"sender.mGen.baseOtCount() = "<<const1<<endl;
        cout<<"sender.mGapOts.size() = "<<const2<<endl;
        cout<<"(sender.mMalType == SilentSecType::Malicious) * 128 = "<<const3<<endl;
        auto count = const1 + const2 + const3;
        cout<<"base count = "<<count<<endl;
        std::vector<std::array<block, 2>> msg2(count);
        for (u64 i = 0; i < msg2.size(); ++i)
        {
            msg2[i][0] = prng.get();
            msg2[i][1] = prng.get();
        }
        sender.setSilentBaseOts(msg2);
        // fake base OTs.
        {
            recver.configure(n, s, threads);
            BitVector choices = recver.sampleBaseChoiceBits(prng);
            std::vector<block> msg(choices.size());
            for (u64 i = 0; i < msg.size(); ++i)
                msg[i] = msg2[i][choices[i]];
            recver.setSilentBaseOts(msg);
        }
    }

    void checkRandom(
        span<block> messages, span<std::array<block, 2>>messages2,
        BitVector& choice, u64 n,
        bool verbose)
    {

        if (messages.size() != n)
            throw RTE_LOC;
        if (messages2.size() != n)
            throw RTE_LOC;
        if (choice.size() != n)
            throw RTE_LOC;
        bool passed = true;

        for (u64 i = 0; i < n; ++i)
        {
            block m1 = messages[i];
            block m2a = messages2[i][0];
            block m2b = (messages2[i][1]);
            u8 c = choice[i];


            std::array<bool, 2> eqq{
                eq(m1, m2a),
                eq(m1, m2b)
            };
            if (eqq[c ^ 1] == true)
            {
                passed = false;
                if (verbose)
                    std::cout << Color::Pink;
            }
            if (eqq[0] == false && eqq[1] == false)
            {
                passed = false;
                if (verbose)
                    std::cout << Color::Red;
            }

            if (eqq[c] == false && verbose)
                std::cout << "m" << i << " " << m1 << " != (" << m2a << " " << m2b << ")_" << (int)c << "\n";

        }

        if (passed == false)
            throw RTE_LOC;
    }

int main(int argc, char** argv){
    CLP cmd;
	cmd.parse(argc, argv);
    auto sockets = cp::LocalAsyncSocket::makePair();
    u64 n = cmd.getOr("n", 1000000);
    cout<<"n = "<<n<<endl;
    bool verbose = cmd.getOr("v", 0) > 1;
    cout<<"verbose = "<<verbose<<endl;
    u64 threads = cmd.getOr("t", 8);
    cout<<"threads = "<<threads<<endl;
    u64 s = cmd.getOr("s", 2);
    cout<<"s = "<<s<<endl;
    PRNG prng(toBlock(cmd.getOr("seed", 0)));
    //PRNG prng1(toBlock(cmd.getOr("seed1", 1)));
    SilentOtExtReceiver recver;
    recver.mMultType = MultType::slv5;
    recver.mNumThreads = threads;
    SilentOtExtSender sender;
    sender.mMultType = MultType::slv5;
    sender.mNumThreads = threads;
    Timer timer;
    auto start = timer.setTimePoint("start");
    fakeBase(n, s, threads, prng, recver, sender);
    //setBaseOts(sender, recv);
    cout<<"fakeBase secessful"<<endl;

    auto type = OTType::Random;
    std::vector<block> messages2(n);
    BitVector choice(n);
    cout<<"set chooses"<<endl;

    //cout<<choice<<endl;
    std::vector<std::array<block,2>> messages(n);
    
    auto p0 = sender.silentSend(messages, prng, sockets[0]);
    cout<<"silentSend"<<endl;

    auto p1 = recver.silentReceive(choice, messages2, prng, sockets[1], type);
    cout<<"silentReceive"<<endl;

    eval(p0, p1);
    cout<<"eval"<<endl;
    checkRandom(messages2, messages, choice, n, verbose);
    auto end = timer.setTimePoint("end");
    auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    u64 com = sockets[0].bytesReceived() + sockets[0].bytesSent();
    cout<<milli<<" ms"<<endl;
    cout<<com<<" bytes"<<endl;
    /*
    int num = 0;
    for (u64 i = 0; i < messages2.size(); ++i){
        cout<<"message: "<<messages2[i]<<endl;
        num = num+1;
    }
    cout<<num<<endl;
    */
   /*
    int num = 0;
    for (u64 i = 0; i < messages.size(); ++i){
        cout<<"message[0]: "<<messages[i][0]<<endl;
        cout<<"message[1]: "<<messages[i][1]<<endl;
        num = num+1;
    }
    
    cout<<num<<endl;
    */
    return 0;
}

/*
int main(int argc, char** argv){
    CLP cmd;
	cmd.parse(argc, argv);
	bool flagSet = false;
	flagSet |= runIf(Silent_example, cmd, Silent);
    return 0;
}
*/