#include "include/Log-Analysis.h"

inline bool cmp(Source a, Source b) { return a.city < b.city; }

void Log_Analysis::get_log()
{
	string str;
	while (getline(in, str))
	{
		Message m;
		string tmp;
		tmp = str.substr(0, str.find(" "));
		m.ip = tmp;
		tmp = str.substr(str.find(":") + 1, str.find(" ", str.find(":")) - str.find(":") - 1);
		m.time = stoi(tmp.substr(0, 2)) * 60 + stoi(tmp.substr(3, 2));
		tmp = str.substr(str.find("\"") + 1, str.find(" ", str.find("\"")) - str.find("\"") - 1);
		m.request = tmp;
		tmp = str.substr(str.find("//") + 2, str.find("/", str.find("//") + 2) - str.find("//") - 2);
		m.web = tmp;
		if (m.web.back() == '/') m.web.pop_back();
		m.web += str.substr(str.find(" ", str.find("\"")) + 1, str.find("\"", str.find(" ", str.find("\""))) - str.find(" ", str.find("\"")) - 1);
		logs.push_back(m);
	}
}

Log_Analysis::Log_Analysis(string file)
{
	in.open(file,ios::in);
	if (!in) cerr << "无法打开日志" << endl;
	else
	{
		get_log();
		cout << "日志读取成功" << endl;
	}
}

void Log_Analysis::time_analysis(string file)
{
	FILE *fp = fopen((char*)file.c_str(), "w");
	if (!fp) cerr << "无法打开文件" << endl;
	cout << "时间上的⽤户访问分布:" << endl;
	fprintf(fp, "时间上的用户访问分布:\n");
	int start = logs.front().time, end = logs.back().time;
	const int divide = 10;
	auto p = logs.begin();
	for (int i = 0; i < (end - start) / divide; i++)
	{
		int cnt = 0, s = start + divide * i, e = start + divide * (i + 1);
		for (; p != logs.end(); p++)
			if (p->time >= s && p->time <= e)
				cnt++;
			else break;
		printf("从%02d:%02d到%02d:%02d有%d请求\n", s / 60, s % 60, e / 60, e % 60, cnt);
		fprintf(fp, "从%02d:%02d到%02d:%02d有%d请求\n", s / 60, s % 60, e / 60, e % 60, cnt);
	}
	fclose(fp);
}

void Log_Analysis::ip_analysis(string file)
{
	ofstream out;
	out.open(file, ios::out);
	if (!out) cerr << "无法打开文件" << endl;
	cout << "基于IP的地域上的⽤户访问分布:" << endl;
	out << "基于IP的地域上的⽤户访问分布:" << endl;
	IPLocator ipl("../data/QQWry.dat");
	vector<Source> res;
	for (auto p = logs.begin(); p != logs.end(); p++)
	{
		string city = ipl.getIpAddr(p->ip);
		city = city.substr(0, city.find(" "));
		decltype(res.begin()) q;
		for (q = res.begin(); q != res.end(); q++)
			if (q->city == city) break;
		if (q != res.end()) q->num++;
		else res.push_back({ city,1 });
	}
	sort(res.begin(), res.end(), cmp);
	for (auto p = res.begin(); p != res.end(); p++)
	{
		cout << p->city << ": " << p->num << " 请求" << endl;
		out << p->city << ": " << p->num << " 请求" << endl;
	}
	out.close();
}

void Log_Analysis::user_analysis(string file)
{
	ofstream out;
	out.open(file, ios::out);
	if (!out) cerr << "无法打开文件" << endl;
	vector<Message> tmp = logs;
	cout << "从单个⽤户为线索的⾏为⽇志分析:" << endl;
	out << "从单个⽤户为线索的⾏为⽇志分析:" << endl;
	for (auto p = tmp.begin(); p != tmp.end(); p++)
	{
		string ip = p->ip;
		cout << "用户" << ip << endl;
		out << "用户" << ip << endl;
		for (auto q = p; q != tmp.end(); q++)
			if (q->ip == ip)
			{
				printf("在%02d:%02d通过", q->time / 60, q->time % 60);
				out << "在" << q->time /60 << ":" << q->time % 60 << "通过";
				cout << q->web;
				out << q->web;
				if (q->request == "GET") { cout << "读取"; out << "读取"; }
				else if (q->request == "PUT") { cout << "更新"; out << "更新"; }
				else if (q->request == "DELETE") { cout << "删除"; out << "删除"; }
				else if (q->request == "POST") { cout << "发送"; out << "发送"; }
				else { cout << q->request; out << q->request; }
				cout << "表单" << endl;
				out << "表单" << endl;
			}
	}
	out.close();
}
