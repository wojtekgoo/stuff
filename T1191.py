cmd = 'cmd.exe /c date /t >> C:\\Users\\Public\\T1191.txt & time /t >> C:\\Users\\Public\\T1191.txt & whoami >> C:\\Users\\Public\\T1191.txt & hostname >> C:\\Users\\Public\\T1191.txt & tasklist /v >> C:\\Users\\Public\\T1191.txt'

n = 2
divided = [cmd[i:i+n] for i in range(0, len(cmd), n)]

i=1
concat = ''

for row in divided:
	print('b' + str(i) + '="' + row + '"')
	concat = concat + '%b' + str(i) + '%'
	i = i + 1

print('\n' + concat)
	