#include "libnavajo/libnavajo.hh"
#include <csignal>
#include <cstring>

WebServer *webServer = nullptr;

void exitFunction( int dummy )
{
  if( webServer != nullptr ) {
    webServer->stopService();
  }
}

class MyDynamicPage : public DynamicPage {
  bool getPage( HttpRequest *request, HttpResponse *response ) override
  {
    // example using session's object
    int *cptExample = nullptr;

    void *myAttribute = request->getSessionAttribute( "myAttribute" );
    if( myAttribute == nullptr ) {
      cptExample  = (int *)malloc( sizeof( int ) );
      *cptExample = 0;
      request->setSessionAttribute( "myAttribute", (void *)cptExample );
    }
    else {
      cptExample = (int *)request->getSessionAttribute( "myAttribute" );
    }

    *cptExample = *cptExample + 1;
    //

    std::string content = "<HTML><BODY>";
    std::string param;
    if( request->getParameter( "param1", param ) ) {
      // int pint=getValue<int>(param);
      content += "param1 has been set to " + param;
    }
    else {
      content += "param1 hasn't been set";
    }

    std::stringstream myAttributess;
    myAttributess << *cptExample;
    content += "<BR/>my session attribute myAttribute contains " + myAttributess.str();

    content += "</BODY></HTML>";

    return fromString( content, response );
  }
};

int main()
{
  // connect signals
  signal( SIGTERM, exitFunction );
  signal( SIGINT, exitFunction );

  webServer = new WebServer;

  webServer->setServerPort( 8080 );
  MyDynamicPage     page1;
  DynamicRepository myRepo;
  myRepo.add( "/dynpage.html", &page1 ); // unusual html extension for a dynamic page !
  webServer->addRepository( &myRepo );

  MemcachedRepository memcachedRepo( "my-prefix" );
  // memcachedRepo.set( "/xyz", "<body>XYZ</body>" );
  // memcachedRepo.set( "/abc", "<body>ABC</body>" );
  webServer->addRepository( &memcachedRepo );

  webServer->startService();

  // Your Processing here !
  //...
  webServer->wait();

  LogRecorder::freeInstance();
  return 0;
}
