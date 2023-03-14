#pragma once
#include <iostream>
#include <cstdio>
#include <vector>
#include <string>
#include <fstream>
#include <algorithm>
#include "IPLocator.hpp"
using namespace std;
typedef struct {
	string ip, request, web;
	int time;
} Message;
typedef struct {
	string city;
	int num;
} Source;
class Log_Analysis
{
	ifstream in;
	vector<Message> logs;
	void get_log();
public:
	Log_Analysis(string file);
	void time_analysis(string file = "../data/time_based");
	void ip_analysis(string file = "../data/ip_based");
	void user_analysis(string file = "../data/user_based");
};

