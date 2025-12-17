import numpy as np
from scipy.io import wavfile
from scipy.fft import fft, fftfreq
freq_pairs = [
    (7500, 7700), # msb
    (8500, 8700),
    (9500, 9700),
    (10500, 10700),
    (11500, 11700),
    (12500, 12700),
    (13500, 13700),
    (14500, 14700) # lsb
]
def parse_audio(audio):
    rate, data = wavfile.read(audio)
    if data.ndim > 1:
        data = data[:,0]
    samples = int(0.1*rate) # duration = 0.1s
    symbols = len(data) // samples
    binarystr = []
    for i in range(symbols):
        chunk = data[i*samples:(i+1)*samples]
        yf = np.abs(fft(chunk * np.hanning(len(chunk))))
        xf = fftfreq(len(chunk), 1/rate)
        xf, yf = xf[:len(xf)//2], yf[:len(yf)//2]
        bits = []
        for f0, f1 in freq_pairs:
            i0 = np.argmin(np.abs(xf - f0))
            i1 = np.argmin(np.abs(xf - f1))
            bits.append('0' if yf[i0] > yf[i1] else '1')
        binarystr.append(''.join(bits))
    return ''.join(binarystr)
print(parse_audio("binaural_beats.wav"))