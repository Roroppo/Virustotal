import sys
import virus_total


argvs = sys.argv 
argc = len(argvs)

#コマンドライン上の引数が二つ入ってない場合に返すエラー
if (argc != 2):
	print 'usage: #python %s analysis_results_id' % argvs[0]
	quit()

#引数二つの場合（二つ以外の場合は考えぬ）
else: 
	analysis = Analysis(int(argvs[1]))
	analysis.virustotal()
	print 'analysis_results updated at id = %s' % argvs[1]