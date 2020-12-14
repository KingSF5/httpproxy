import urllib.request
from bs4 import BeautifulSoup
import urllib.parse
import re
import os
sensitive_words = ""
for line in open("../list/sensitive_words.txt",encoding='utf-8'):
	line=line.strip('\n')
	sensitive_words=sensitive_words+line+'|'


sensitive_words = sensitive_words[0:-1]
print(sensitive_words)

url = 'https://www.baidu.com/s?wd=youxing'
header = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36'}
req = urllib.request.Request(url, headers=header)
res = urllib.request.urlopen(req)
html = res.read().decode('utf-8')
res.close()
result = re.search(sensitive_words, html)
print(result)

'''
bsObj = BeautifulSoup(html)
print(bsObj)

bsObj.findAll(re.compile(sensitive_words)}):
	print(link.get_text())
	print("https://baike.baidu.com%s"%link["href"])
'''
