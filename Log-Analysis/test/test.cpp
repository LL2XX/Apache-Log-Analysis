#include "../libLogAnalysis/include/Log-Analysis.h"
int main()
{
	Log_Analysis log("../data/access_log_20220603-155424.log");
	log.time_analysis();
	log.ip_analysis();
	log.user_analysis();
	return 0;
}
