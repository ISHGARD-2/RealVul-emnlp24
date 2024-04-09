import json
import csv

def read_json(path):
    f = open(path, 'r')
    content = f.read()
    data = json.loads(content)
    f.close()
    return data


def write_json(data, path):
    b = json.dumps(data)
    f2 = open(path, 'w')
    f2.write(b)
    f2.close()

def json_to_csv(json_file, csv_file):
    # 读取JSON文件
    data = read_json(json_file)

    # 打开CSV文件并写入数据
    with open(csv_file, 'w', newline='', encoding='utf-8') as csv_data:
        csv_writer = csv.writer(csv_data)

        # 写入表头
        header = list(data[0].keys())
        csv_writer.writerow(header)

        # 写入数据
        for row in data:
            csv_writer.writerow(row.values())
