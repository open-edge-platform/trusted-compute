import re

def process_fps_file(filename):
    pattern = re.compile(
        r'FpsCounter\(last [\d\.]+sec\): total=([\d\.]+) fps, number-streams=(\d+),'
    )
    stream_data = {str(i): [] for i in range(1, 11)}

    with open(filename, 'r') as f:
        for line in f:
            match = pattern.search(line)
            if match:
                total_fps = float(match.group(1))
                num_streams = match.group(2)
                if num_streams in stream_data and len(stream_data[num_streams]) < 120:
                    stream_data[num_streams].append(total_fps)

    for i in range(1, 11):
        values = stream_data[str(i)]
        if len(values) == 0:
            print(f"Stream {i}: Not available")
        else:
            avg = sum(values) / len(values)
            print(f"Stream {i}: Average of {len(values)} values = {avg:.2f}")

# Example usage:
process_fps_file('dl_streamer_fps_logs.txt')
