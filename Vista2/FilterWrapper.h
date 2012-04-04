#include "Vista2.h"

namespace Vista2 
{
	public ref class VistaFilterWrapper
	{
	private:
		VistaFilter * vistaFilter;
	public:
		VistaFilterWrapper()
		{
			vistaFilter = new VistaFilter();
		}

		DWORD StartFireWall(LPSTR szIpAddrToBlock)
		{	
			return vistaFilter->StartFireWall(szIpAddrToBlock);
		}

		DWORD StopFireWall() 
		{
			return vistaFilter->StopFireWall();
		}
	};
}