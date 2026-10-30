from . import report

if __name__ == "__main__":
    rep = report.build()
    report.write(rep)
    print("wrote out/report.json and docs/REPORT.md")
