import sharp from "sharp";

export const resizeImage = async (buffer,toFile,sizes = [500,500]) => {
    await sharp(buffer)
        .resize(sizes[0],sizes[1])
        .toFormat("jpeg")
        .jpeg({quality: 90})
        .toFile(toFile)
}