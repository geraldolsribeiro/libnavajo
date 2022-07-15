// ----------------------------------------------------------------------
// Copyright (C) 2004-2020 Geraldo Ribeiro <geraldo@intmain.io>
// ----------------------------------------------------------------------

#ifndef GR_COMMON_DEBUG_HPP
#define GR_COMMON_DEBUG_HPP

#include <cstring> // strerror( errno )
#include <exception>
#include <stdexcept>
#include <string>


// don't use me any more
// GR_DEPRECATED(void OldFunc(int a, float b));
#ifdef __GNUC__
#define GR_DEPRECATED( func ) func __attribute__( ( deprecated ) )
#elif defined( _MSC_VER )
#define GR_DEPRECATED( func ) __declspec( deprecated ) func
#else
#pragma message( "WARNING: You need to implement DEPRECATED for this compiler" )
#define GR_DEPRECATED( func ) func
#endif


// Default
#ifndef GR_USE_JUMP_TRACE
#define GR_USE_JUMP_TRACE 0
#endif

#ifndef GR_USE_TRACE_MSG
#define GR_USE_TRACE_MSG 0
#endif

#if GR_USE_JUMP_TRACE || GR_USE_TRACE_MSG
#include <iostream>
#endif

#if GR_USE_JUMP_TRACE
#define GR_JUMP_TRACE std::cerr << "\nGRJMP:" << __FILE__ << "/" << __LINE__ << "/" << __PRETTY_FUNCTION__ << std::endl;
#else
#define GR_JUMP_TRACE {}
#endif

#if GR_USE_TRACE_MSG
#define GR_TRACE_MSG( x )                                                                                              \
  std::cerr << "\nGRMSG:" << __FILE__ << "/" << __LINE__ << "/" << __PRETTY_FUNCTION__ << "\n" << x << std::endl;
#else
#define GR_TRACE_MSG( x ) {}
#endif


//#define THROWMSG(x) throw __FILE__  " "  x ;

#ifdef __WIN32
// O mingw não possui to_string definida
#define GR_TO_STRING( x ) #x
#else
#define GR_TO_STRING( x ) std::to_string( x )
#endif


#define GR_ASSERT( test, msg )                                                                                         \
  if( !( test ) ) {                                                                                                    \
    std::string err( "GR_ASSERT: " );                                                                                  \
    err.append( msg );                                                                                                 \
    err.append( "\nArquivo: " );                                                                                       \
    err.append( __FILE__ );                                                                                            \
    err.append( "\nLinha: " );                                                                                         \
    err.append( GR_TO_STRING( __LINE__ ) );                                                                            \
    err.append( "\nFun??o: " );                                                                                        \
    err.append( __PRETTY_FUNCTION__ );                                                                                 \
    throw std::runtime_error( err.c_str() );                                                                           \
  }

#define GR_THROW_MSG( e, msg )                                                                                         \
  throw e(                                                                                                             \
      std::string( msg )                                                                                               \
          .append( ":" )                                                                                               \
          .append( __FILE__ )                                                                                          \
          .append( ":" )                                                                                               \
          .append( GR_TO_STRING( __LINE__ ) )                                                                          \
          .append( ":" )                                                                                               \
          .append( __PRETTY_FUNCTION__ ) );

#define GR_THROW( e ) GR_THROW_MSG( e, #e )


// Gerador de exceção
#define GR_EXCEPTION( NAME )                                                                                           \
  class NAME : public std::invalid_argument {                                                                          \
  public:                                                                                                              \
    explicit NAME( const char *message ) : std::invalid_argument( message )                                            \
    {                                                                                                                  \
    }                                                                                                                  \
    explicit NAME( const std::string &message ) : std::invalid_argument( message )                                     \
    {                                                                                                                  \
    }                                                                                                                  \
    virtual ~NAME() throw()                                                                                            \
    {                                                                                                                  \
    }                                                                                                                  \
  };

#endif
