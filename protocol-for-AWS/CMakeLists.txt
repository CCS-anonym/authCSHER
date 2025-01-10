cmake_minimum_required(VERSION 3.12)
project(protocol-for-AWS)

set(CMAKE_CXX_STANDARD 17)


#if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
	set(CMAKE_TOOLCHAIN_FILE "E:/programs/vcpkg-master/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
	message(" [INFO] VCPKG CMAKE_TOOLCHAIN_FILE = ${CMAKE_TOOLCHAIN_FILE}")
#endif()


find_package(SEAL REQUIRED
        PATHS $ENV{HOME}/git/SEAL/native/Release)


find_package(cpprestsdk REQUIRED)

find_package(AWSSDK REQUIRED COMPONENTS s3)

find_package(cryptopp REQUIRED)

find_package(Curses REQUIRED)

find_package(OpenSSL REQUIRED)

include_directories( ${CURSES_INCLUDE_DIRS} )


add_executable(Data_Owner
        Data_Owner/main.cpp
        Data_Owner/Data_Owner.h
        Data_Owner/Data_Owner.cpp
        Secret_Sharing.cpp
        Secret_Sharing.h
        K_MAC.h
        K_MAC.cpp
        MAC.cpp
        MAC.h
        Tests.cpp
        Tests.h
        Servers_Protocol.cpp
        Servers_Protocol.h
        Utility.h
        Utility.cpp)

add_executable(Auxiliary_Server
        Auxiliary_Server/main.cpp
        Auxiliary_Server/Auxiliary_Server.h
        Auxiliary_Server/Auxiliary_Server.cpp
        Secret_Sharing.cpp
        Secret_Sharing.h
        K_MAC.h
        K_MAC.cpp
        MAC.cpp
        MAC.h
        Servers_Protocol.cpp
        Servers_Protocol.h
        Utility.h
        Utility.cpp)

add_executable(Destination_Server
        Destination_Server/main.cpp
        Destination_Server/Destination_Server.h
        Destination_Server/DS_Performance_metrics.h
        Destination_Server/Destination_Server.cpp
        Tests.cpp
        Secret_Sharing.cpp
        Secret_Sharing.h
        K_MAC.h
        K_MAC.cpp
        MAC.cpp
        MAC.h
        Servers_Protocol.cpp
        Servers_Protocol.h
        Utility.h
        Utility.cpp)

add_executable(Test_Protocol
        Test_Protocol/main.cpp
        Test_Protocol/Test_Protocol.h
        Test_Protocol/Test_Protocol.cpp
        Tests.cpp
        Tests.h
        Secret_Sharing.cpp
        Secret_Sharing.h
        MAC.cpp
        MAC.h
        K_MAC.h
        K_MAC.cpp
        Servers_Protocol.cpp
        Servers_Protocol.h
        Utility.h
        Utility.cpp)


add_executable(End_2_End
        Data_Owner/Data_Owner.h
        Data_Owner/Data_Owner.cpp
        Auxiliary_Server/Auxiliary_Server.h
        Auxiliary_Server/Auxiliary_Server.cpp
        Destination_Server/Destination_Server.h
        Destination_Server/Destination_Server.cpp
        Tests.cpp
        Tests.h
        Secret_Sharing.cpp
        Secret_Sharing.h
        MAC.cpp
        MAC.h
        Servers_Protocol.cpp
        Servers_Protocol.h
        Utility.h
        Utility.cpp)

target_link_libraries(Data_Owner
         SEAL::seal
	 cryptopp::cryptopp
         ${AWSSDK_LINK_LIBRARIES})

target_link_libraries(Auxiliary_Server
         SEAL::seal
         cpprestsdk::cpprest
	 cryptopp::cryptopp
	 ${CURSES_LIBRARIES}
         ${AWSSDK_LINK_LIBRARIES})

target_link_libraries(Destination_Server
         SEAL::seal
         cpprestsdk::cpprest
	 cryptopp::cryptopp
         ${AWSSDK_LINK_LIBRARIES})

target_link_libraries(End_2_End
        SEAL::seal
	cryptopp::cryptopp)

target_link_libraries(Test_Protocol
         SEAL::seal
         cpprestsdk::cpprest
	 cryptopp::cryptopp
	 ${CURSES_LIBRARIES}
         ${AWSSDK_LINK_LIBRARIES}
         OpenSSL::SSL OpenSSL::Crypto)


