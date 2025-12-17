from PIL import Image
import base64

img = Image.open("colorstrip.png").convert("RGBA")
width, height = img.size
colors = []
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" # base 64 character mapping

for y in range(height):
    r,g,b,a = img.getpixel((0,y))
    colors.append((r,g,b,a))
print(colors)

indices = [(3*r + 5*g + 7*b + 11*a) % 64 for r, g, b, a in colors] # QOI encoding index hash function
print(base64.b64decode(''.join(alphabet[i] for i in indices)))