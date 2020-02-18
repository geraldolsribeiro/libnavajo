//********************************************************
/**
 * @file  LocalRepository.cc
 *
 * @brief Handles local web repository
 *
 * @author T.Descombes (thierry.descombes@gmail.com)
 *
 * @version 1
 * @date 19/02/15
 */
//********************************************************

//#define GR_JUMP_TRACE std::cerr << "\nGRJMP:" << __FILE__ << "/" << __LINE__ << "/" << __PRETTY_FUNCTION__ <<
// std::endl;
#define GR_JUMP_TRACE                                                                                                  \
  {                                                                                                                    \
  }

#include "libnavajo/LocalRepository.hh"
#include "libnavajo/LogRecorder.hh"
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <stdlib.h>
#include <streambuf>
#include <string.h>
#include <sys/stat.h>

/**********************************************************************/

LocalRepository::LocalRepository( const std::string &alias, const std::string &dirPath )
{
  GR_JUMP_TRACE;
  char resolved_path[4096];

  pthread_mutex_init( &_mutex, NULL );

  aliasName = alias;
  while( aliasName.size() && aliasName[0] == '/' ) {
    aliasName.erase( 0, 1 );
  }
  while( aliasName.size() && aliasName[aliasName.size() - 1] == '/' ) {
    aliasName.erase( aliasName.size() - 1 );
  }

  if( realpath( dirPath.c_str(), resolved_path ) != NULL ) {
    fullPathToLocalDir = resolved_path;
    loadFilename_dir( aliasName, fullPathToLocalDir );
  }
}

/**********************************************************************/

void LocalRepository::reload()
{
  GR_JUMP_TRACE;
  pthread_mutex_lock( &_mutex );
  filenamesSet.clear();
  loadFilename_dir( aliasName, fullPathToLocalDir );
  pthread_mutex_unlock( &_mutex );
}

/**********************************************************************/

bool LocalRepository::loadFilename_dir( const std::string &alias, const std::string &path, const std::string &subpath )
{
  GR_JUMP_TRACE;
  struct dirent *entry;
  DIR *          dir;
  struct stat    s;
  std::string    fullPath = path + subpath;

  dir = opendir( fullPath.c_str() );
  if( dir == NULL ) {
    return false;
  }
  while( ( entry = readdir( dir ) ) != NULL ) {
    if( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) || !strlen( entry->d_name ) ) {
      continue;
    }

    std::string filepath = fullPath + '/' + entry->d_name;

    if( stat( filepath.c_str(), &s ) == -1 ) {
      NVJ_LOG->append(
          NVJ_ERROR,
          std::string( "LocalRepository - stat error reading file '" ) + filepath
              + "': " + std::string( strerror( errno ) ) );
      continue;
    }

    int type = s.st_mode & S_IFMT;
    if( type == S_IFREG || type == S_IFLNK ) {
      std::string filename = alias + subpath + "/" + entry->d_name;
      while( filename.size() && filename[0] == '/' ) {
        filename.erase( 0, 1 );
      }
      filenamesSet.insert( filename );
    }

    if( type == S_IFDIR ) {
      loadFilename_dir( alias, path, subpath + "/" + entry->d_name );
    }
  }

  closedir( dir );

  return true;
}

/**********************************************************************/

bool LocalRepository::fileExist( const std::string &url )
{
  GR_JUMP_TRACE;
  return filenamesSet.find( url ) != filenamesSet.end();
}

/**********************************************************************/

bool LocalRepository::getFile( HttpRequest *request, HttpResponse *response )
{
  GR_JUMP_TRACE;
  std::string    url = request->getUrl();
  size_t         webpageLen;
  unsigned char *webpage;
  pthread_mutex_lock( &_mutex );

  if( url.compare( 0, aliasName.size(), aliasName ) || !fileExist( url ) ) {
    pthread_mutex_unlock( &_mutex );
    return false;
  };

  pthread_mutex_unlock( &_mutex );

  std::string filename = url;

  if( aliasName.size() ) {
    GR_JUMP_TRACE;
    filename.replace( 0, aliasName.size(), fullPathToLocalDir );
  }
  else {
    GR_JUMP_TRACE;
    filename = fullPathToLocalDir + '/' + filename;
  }

  FILE *pFile = fopen( filename.c_str(), "rb" );
  if( pFile == NULL ) {
    GR_JUMP_TRACE;
    char logBuffer[150];
    snprintf( logBuffer, 150, "Webserver : Error opening file '%s'", filename.c_str() );
    NVJ_LOG->append( NVJ_ERROR, logBuffer );
    return false;
  }

  // obtain file size.
  fseek( pFile, 0, SEEK_END );
  webpageLen = ftell( pFile );
  rewind( pFile );

  if( ( webpage = (unsigned char *)malloc( webpageLen + 1 * sizeof( char ) ) ) == NULL ) {
    GR_JUMP_TRACE;
    // fclose( pFile ); // GLSR FIXME resource leak
    return false;
  }
  size_t nb = fread( webpage, 1, webpageLen, pFile );
  if( nb != webpageLen ) {
    GR_JUMP_TRACE;
    char logBuffer[150];
    snprintf( logBuffer, 150, "Webserver : Error accessing file '%s'", filename.c_str() );
    NVJ_LOG->append( NVJ_ERROR, logBuffer );
    // free( webpage );
    // fclose( pFile );
    return false;
  }

  fclose( pFile );
  response->setContent( webpage, webpageLen );
  return true;
}
