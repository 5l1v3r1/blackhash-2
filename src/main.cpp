// Copyright 2013, 16 Systems


#include "main.hpp"


int main(int argc, char* argv[])
{
    std::cerr.imbue(std::locale(""));

    const std::string usage = "usage: bh hash_file filter_file create|test\n";

    if( argc != 4 )
    {
        std::cerr << VERSION;
        std::cerr << usage;
        return 1;
    }

    const std::string hash_file = argv[1];
    const std::string filter_file = argv[2];
    const std::string operation = argv[3];

    std::string fbytes = "01010101";

    if( operation == "test" )
    {
        CREATE = false;
    }

    if( !CREATE )
    {
        fbytes = load_filter( filter_file );
    }

    // Create bitsets
    std::bitset<M> * sbits = new (std::nothrow) std::bitset<M>();
    std::bitset<M> * gbits = new (std::nothrow) std::bitset<M>( fbytes );
    
    if ( sbits == 0 or gbits == 0 )
    {
        std::cerr << "sbits or gbits are NULL." << '\n';
        return 1;
    }

    // Load Password Hashes
    std::ifstream fp ( hash_file.c_str() );

    if ( !fp.is_open() )
    {
        std::cerr << "Cannot open " << hash_file << "\n";
        return 1;
    }

    load_pw_hashes( fp );
    fp.close();

    // Set or get bits
    std::multimap<std::string, std::string>::const_iterator pwhit;

    for( pwhit = PHASHES.begin(); pwhit != PHASHES.end(); ++pwhit )
    {
        CryptoPP::Weak::MD4 hash1;
        CryptoPP::Weak::MD5 hash2;

        char digest[ HDS1 ];
        hash1.Update( (const byte*)pwhit->second.c_str(), pwhit->second.size() );
        hash1.Final( (byte *)digest );

        char digest2[ HDS2 ];
        hash2.Update( (const byte*)pwhit->second.c_str(), pwhit->second.size() );
        hash2.Final( (byte *)digest2 );

        const std::string string_digest( digest, HDS1 );
        const std::string first_8_bytes = string_digest.substr(0,8);
        const std::string final_8_bytes = string_digest.substr(8,8);

        const std::string string_digest2( digest2, HDS2 );
        const std::string first_8_bytes2 = string_digest2.substr(0,8);
        const std::string final_8_bytes2 = string_digest2.substr(8,8);

        const std::uint64_t * data_ptr;
        data_ptr = reinterpret_cast<const std::uint64_t*>(first_8_bytes.data());
        const std::uint64_t bytes = *data_ptr;

        const std::uint64_t * data_ptr2;
        data_ptr2 = reinterpret_cast<const std::uint64_t*>(final_8_bytes.data());
        const std::uint64_t bytes2 = *data_ptr2;

        const std::uint64_t * data_ptr3;
        data_ptr3 = reinterpret_cast<const std::uint64_t*>(first_8_bytes2.data());
        const std::uint64_t bytes3 = *data_ptr3;

        const std::uint64_t * data_ptr4;
        data_ptr4 = reinterpret_cast<const std::uint64_t*>(final_8_bytes2.data());
        const std::uint64_t bytes4 = *data_ptr4;

        std::uint64_t pos = random_int(bytes, bytes2);
        std::uint64_t pos2 = random_int(bytes3, bytes4);

        std::vector<std::uint64_t> positions;
        positions.push_back(pos);
        positions.push_back(pos2);

        if( CREATE )
        {
            // Set bits
            bitter( sbits, positions, 1 );
        }

        else
        {
            // Test bits
            if ( bitter( gbits, positions, 0 ) )
            {
                // Show weak hash
                std::cout << pwhit->first << ":" << pwhit->second << "\n";
            }           
        }
    }

    std::cerr << "Number of password hashes loaded from file: " << PHASHES.size() << "\n";

    if( CREATE )
    {
        save_filter( sbits, filter_file );
        std::cerr << "Number of bits set in the filter: " << sbits->count() << "\n";
        std::cerr << "Size of bitset: " << sbits->size() << "\n";
    }

    else
    {
        std::cerr << "Number of bits set in the filter: " << gbits->count() << "\n";
        std::cerr << "Size of bitset: " << gbits->size() << "\n";
    }

    delete sbits;
    delete gbits;

    return 0;
}

