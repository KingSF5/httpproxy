from PIL import Image 
import numpy as np
import urllib
from keras.models import load_model 
#import os
#os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

WIDTH = 192
HEIGHT = 192
CHANNEL = 1
def imgProcess(img, mode):
    img_arr = np.array(img)
    if (mode == 'grey'):
        img_arr[:,:,0] = 0.2989 * img_arr[:,:,0] + 0.5870 * img_arr[:,:,1] + 0.1140 * img_arr[:,:,2]
    return img_arr

def LoadModel(model,img_path):
    img = Image.open(img_path).resize((WIDTH,HEIGHT))
    #Image._show(img)
    img_arr = np.array(img) # 转化成numpy数组
    if (len(img_arr.shape)>=2):#img_arr.shape[2] 可能不存在....
        img_arr = imgProcess(img, 'grey')
    realimg = []
    img_arr = img_arr[:,:,0:1]
    realimg.append(img_arr)
    realimg = np.array(realimg)
    realimg.reshape(1 ,192, 192 , 1)
    realimg = realimg.astype('float32') / 255
    a=model.predict(realimg)
    #print(a)
    if  a[0][1]-a[0][0] > 0.5:
        print("huangse")
    #return a[0][1]-a[0][0]
    '''
    if a[0][1]-a[0][0] > 0.8:
        print("嘤嘤嘤，好害羞啊啊啊啊啊啊啊啊啊啊啊")

    elif a[0][1]-a[0][0] > 0.7:
        print("嗯~啊~")

    elif a[0][1]-a[0][0] > 0.6:
        print("哇哇哇哇哇哇哇哇马叉虫")

    elif a[0][1]-a[0][0] > 0.5:
        print("你个骚蓝")

    elif a[0][1]-a[0][0] > 0.4:
        print("WOC很像欸（认真脸")

    elif a[0][1]-a[0][0] > 0.3:
        print("ahhhh别说了，渣男")

    elif a[0][1]-a[0][0] > 0:
        print("我不管，渣！")
    else :
        print("嘿嘿嘿好像不是啊")
    '''
def download_little_file(from_url,to_path):
    conn = urllib.request.urlopen(from_url)
    f = open(to_path,'wb')
    f.write(conn.read())
    f.close()
def Main():
    model = load_model('PronDetect(e30b200).h5')
    while(1): 
        path = input("Input the image path: ")
        LoadModel(model,path)

import sys
if __name__ == "__main__":
    '''
    接收第一个参数代表图片的路径
    '''
    path = sys.argv[1]
    model = load_model('plugin/PronDetect(e30b200).h5')
    download_little_file(path, "tmp.jpg")
    path = "tmp.jpg"
    LoadModel(model,path)