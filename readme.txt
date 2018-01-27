python2.7.5で作成してます。

python2とpython3は互換性が無いためpython３では使用できません。

もしもpython3でしか使用できない等の環境の場合は　2to3という変換ツールを入れてあるのでそれを使ってください（提供されているライブラリなのできちんと変換出来るのかは知りません）。

変換ツールを実行する場合は　python 2to3.py -w virus_total.py　を行ってください。

一応　-w　をつけておけば元のプログラムは .bak という形で残るはずです。

-------------------------------------------------------------------------
実行する場合

〇 python api_key.py をまず行ってください。

自動的にテーブル:virustotal_api_keysの中が更新されます。

次にanalysis_resultsの中身は埋めてください。要必要　id,analyzed_url

〇 python analysis.py 更新したいテーブルanalysis_resultsのid　を行ってください。

　analysis_resultsのidのanalyzed_time,analysis_result,updated_atが更新されます。
