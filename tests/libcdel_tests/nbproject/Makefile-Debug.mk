#
# Generated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add customized code.
#
# This makefile implements configuration specific macros and targets.


# Environment
MKDIR=mkdir
CP=cp
GREP=grep
NM=nm
CCADMIN=CCadmin
RANLIB=ranlib
CC=gcc
CCC=g++
CXX=g++
FC=gfortran
AS=as

# Macros
CND_PLATFORM=GNU-Linux-x86
CND_DLIB_EXT=so
CND_CONF=Debug
CND_DISTDIR=dist
CND_BUILDDIR=build

# Include project Makefile
include Makefile

# Object Directory
OBJECTDIR=${CND_BUILDDIR}/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/_ext/1445274692/base16.o \
	${OBJECTDIR}/_ext/1445274692/base2.o \
	${OBJECTDIR}/_ext/1445274692/base32.o \
	${OBJECTDIR}/_ext/1445274692/base58.o \
	${OBJECTDIR}/_ext/1445274692/base64.o \
	${OBJECTDIR}/main.o


# C Compiler Flags
CFLAGS=-m64

# CC Compiler Flags
CCFLAGS=
CXXFLAGS=

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=`pkg-config --libs libcrypto`  

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	"${MAKE}"  -f nbproject/Makefile-${CND_CONF}.mk ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/libcdel_tests

${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/libcdel_tests: ${OBJECTFILES}
	${MKDIR} -p ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}
	${LINK.c} -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/libcdel_tests ${OBJECTFILES} ${LDLIBSOPTIONS}

${OBJECTDIR}/_ext/1445274692/base16.o: ../../src/base16.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -g -Wall `pkg-config --cflags libcrypto` -std=c11  -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/base16.o ../../src/base16.c

${OBJECTDIR}/_ext/1445274692/base2.o: ../../src/base2.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -g -Wall `pkg-config --cflags libcrypto` -std=c11  -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/base2.o ../../src/base2.c

${OBJECTDIR}/_ext/1445274692/base32.o: ../../src/base32.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -g -Wall `pkg-config --cflags libcrypto` -std=c11  -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/base32.o ../../src/base32.c

${OBJECTDIR}/_ext/1445274692/base58.o: ../../src/base58.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -g -Wall `pkg-config --cflags libcrypto` -std=c11  -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/base58.o ../../src/base58.c

${OBJECTDIR}/_ext/1445274692/base64.o: ../../src/base64.c 
	${MKDIR} -p ${OBJECTDIR}/_ext/1445274692
	${RM} "$@.d"
	$(COMPILE.c) -g -Wall `pkg-config --cflags libcrypto` -std=c11  -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/1445274692/base64.o ../../src/base64.c

${OBJECTDIR}/main.o: main.c 
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.c) -g -Wall `pkg-config --cflags libcrypto` -std=c11  -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/main.o main.c

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r ${CND_BUILDDIR}/${CND_CONF}
	${RM} ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/libcdel_tests

# Subprojects
.clean-subprojects:

# Enable dependency checking
.dep.inc: .depcheck-impl

include .dep.inc
