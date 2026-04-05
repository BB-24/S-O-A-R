from jinja2 import Environment, FileSystemLoader
import os

env = Environment(loader=FileSystemLoader("report_generator/templates"))


def generate_report(data, output_path="reports/report.html"):
    template = env.get_template("report.html")
    html = template.render(data=data)

    os.makedirs("reports", exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] Report saved: {output_path}")