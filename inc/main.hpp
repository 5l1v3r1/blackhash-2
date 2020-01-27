// Copyright 2013, 16 Systems


// Standard C++
#include <algorithm>
#include <cstdint>
#include <functional>
#include <iostream>
#include <fstream>
#include <bitset>
#include <vector>
#include <map>
#include <string>
#include <sstream>
#include <locale>
#include <random>


// Crypto++
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md4.h>
#include <cryptopp/md5.h>


// Globals
// This combination of M, N and K make P = 0.0008
const static std::uint64_t M = 1024*1024*64; // number of bits (64MB)
const static std::uint64_t N = 1000000; // unused (number of hashes 1 million)
const static std::uint64_t K = 2; // unused (number of hash functions)

std::multimap<std::string, std::string> PHASHES;
const static std::uint64_t HDS1( CryptoPP::Weak::MD4::DIGESTSIZE );
const static std::uint64_t HDS2( CryptoPP::Weak::MD5::DIGESTSIZE );
bool CREATE = true;

const static std::string VERSION("Blackhash 0.2\n");


typedef CryptoPP::byte byte;

void low( std::string& s )
{
    // make s lowercase
    std::transform( s.begin(), s.end(), s.begin(), ::tolower );
}


void split( std::string& s, char d, std::vector<std::string>& v )
{
     // split a string (s) on delimited (d) and put results in vector (v)
     std::stringstream ss(s);
     std::string item;
     while ( std::getline(ss, item, d ))
     {
        v.push_back(item);
     }  
}


void trim( std::string& s )
{
    // remove all whitespace from string
    s.erase( std::remove_if( s.begin(), 
                             s.end(),
                             std::bind( std::isspace<char>, std::placeholders::_1, std::locale::classic() ) ), 
                             s.end() );
}


std::string load_filter( const std::string& in_file )
{
    // Read bitset in from file.
    // All at once... hope there is enough memory.
    std::string filebytes;

    std::ifstream fd ( in_file.c_str() );
    std::getline ( fd, filebytes );
    fd.close();

    return filebytes;
}


void save_filter( std::bitset<M> * bits, const std::string& out_file )
{
    // Write bitset to a file.
    std::ofstream fd ( out_file.c_str() );
    fd << bits->to_string();
    fd.close();
}


bool bitter( std::bitset<M> * bits, const std::vector<std::uint64_t>& bit_positions, const bool set )
{
    // Either set or get bits depending on the operation.

    std::vector<std::uint64_t>::const_iterator bpit;

    bool result = true;

    if( set )
    {
        for( bpit = bit_positions.begin(); bpit != bit_positions.end(); ++bpit )
        {
            // set bit at this position
            //std::cerr << *bpit << "\n";
            bits->set(*bpit);
        }
    }

    else
    {
        for( bpit = bit_positions.begin(); bpit != bit_positions.end(); ++bpit )
        {
            if( !bits->test(*bpit) )
            {
                // If any bit not set, then return false
                // The hash is not present in the bitset
                result = false;
                break;
            }
        }
    }

    return result;
}


struct generic
{
    // <user>:<hash> A generic format for loading hashes
    std::string user;
    std::string hash;
};


struct pwdump
{
    // pwdump format (http://ftp.samba.org/pub/samba/pwdump/README)
    // <user>:<id>:<lanman pw>:<NT pw>:comment:homedir:
    // Either hash may be empty (NO PASSWORD*)

    std::string user;
    std::string uid;
    std::string lm_hash;
    std::string nt_hash;
    std::string comment;
    std::string homedir;
};


std::uint64_t random_int( const std::uint64_t first, const std::uint64_t second )
{
    // Pick a random number from 1 to M
    // Use the password hash bits as the seeds to the rng
    std::mt19937_64 rng(first);
    rng.seed(second);

    std::uniform_int_distribution<std::uint64_t> range(1, M);
    return range(rng);
}


void load_pw_hashes( std::ifstream& fp )
{
    // Load the password hashes from a file into a std::multimap
    // Formats accepted
    // <hash>
    // <user>:<hash>
    // <user>:<id>:<lanman pw>:<NT pw>:comment:homedir:

    // load_pw_hashes() guarantees lowercase hashes and no white space at the ends of the hashes

    std::string line;

    while ( !fp.eof() )
    {
        std::getline( fp, line );
        std::vector<std::string> pw_parts;

        // Assume pwdump or generic format
        if ( line.find(':') != std::string::npos )
        {
            split( line, ':', pw_parts );
            std::uint64_t n = std::count(line.begin(), line.end(), ':');

            if( n == 6 )
            {
                pwdump account_info = {
                        pw_parts[0],
                        pw_parts[1],
                        pw_parts[2],
                        pw_parts[3],
                        pw_parts[4],
                        pw_parts[5],
                };

                // LM
                low( account_info.lm_hash );
                trim( account_info.lm_hash );

                if ( !account_info.lm_hash.empty() and account_info.lm_hash.find("nopassword") == std::string::npos )
                {
                    //std::cerr << "Loading " << account_info.user << " " << account_info.lm_hash << "\n";
                    PHASHES.insert( std::pair<std::string, std::string>( account_info.user, account_info.lm_hash ));
                }               

                // NT
                low( account_info.nt_hash );
                trim( account_info.nt_hash );

                if ( !account_info.nt_hash.empty() and account_info.nt_hash.find("nopassword") == std::string::npos )
                {
                    //std::cerr << "Loading " << account_info.user << " " << account_info.nt_hash << "\n";
                    PHASHES.insert( std::pair<std::string, std::string>( account_info.user, account_info.nt_hash ));
                }               
            }

            else if ( n == 1 )
            {
                generic account_info = {
                    pw_parts[0],
                    pw_parts[1],
                };

                low( account_info.hash );
                trim( account_info.hash );

                if ( !account_info.hash.empty() )
                {
                    //std::cerr << "Loading " << account_info.user << " " << account_info.hash << "\n";
                    PHASHES.insert( std::pair<std::string, std::string>( account_info.user, account_info.hash ) );
                }               
            }

            else
            {
                std::cerr << "WARNING INVALID HASH FORMAT - " << line << "\n";
            }
        }
        
        // Assume one hash per line
        // In this case, user is shown as a single '?'
        else
        {
            low( line );
            trim( line );
            
            if ( !line.empty() )
            {
                PHASHES.insert( std::pair<std::string, std::string>( "?", line ) );
            }               
        }
    }
}

