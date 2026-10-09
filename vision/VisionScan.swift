// VisionScan: OCR + barcode detection for a list of images, JSON lines on stdout.
// Usage: visionscan img1.png img2.png ...   (or paths on stdin, one per line)
import Foundation
import Vision
import AppKit

struct Box: Codable { let x: Double; let y: Double; let w: Double; let h: Double }
struct TextHit: Codable { let text: String; let conf: Double; let box: Box }
struct CodeHit: Codable { let payload: String; let symbology: String; let box: Box }
struct Result: Codable { let path: String; let width: Int; let height: Int; let texts: [TextHit]; let codes: [CodeHit]; let error: String? }

func box(_ r: CGRect, _ w: Int, _ h: Int) -> Box {
    // Vision uses normalized coords with origin bottom-left; convert to pixel top-left.
    let W = Double(w), H = Double(h)
    return Box(x: r.minX * W, y: (1 - r.maxY) * H, w: r.width * W, h: r.height * H)
}

func scan(_ path: String) -> Result {
    guard let img = NSImage(contentsOfFile: path),
          let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
        return Result(path: path, width: 0, height: 0, texts: [], codes: [], error: "cannot read image")
    }
    let w = cg.width, h = cg.height
    let ocr = VNRecognizeTextRequest()
    ocr.recognitionLevel = .accurate
    ocr.usesLanguageCorrection = false   // keep keys/tokens verbatim
    let bar = VNDetectBarcodesRequest()
    do {
        try VNImageRequestHandler(cgImage: cg).perform([ocr, bar])
    } catch {
        return Result(path: path, width: w, height: h, texts: [], codes: [], error: "\(error)")
    }
    let texts: [TextHit] = (ocr.results ?? []).compactMap { obs in
        guard let c = obs.topCandidates(1).first else { return nil }
        return TextHit(text: c.string, conf: Double(c.confidence), box: box(obs.boundingBox, w, h))
    }
    let codes: [CodeHit] = (bar.results ?? []).map { obs in
        CodeHit(payload: obs.payloadStringValue ?? "", symbology: obs.symbology.rawValue, box: box(obs.boundingBox, w, h))
    }
    return Result(path: path, width: w, height: h, texts: texts, codes: codes, error: nil)
}

var paths = Array(CommandLine.arguments.dropFirst())
if paths.isEmpty {
    while let line = readLine(strippingNewline: true) { if !line.isEmpty { paths.append(line) } }
}
let enc = JSONEncoder()
let out = FileHandle.standardOutput
for p in paths {
    if let data = try? enc.encode(scan(p)) { out.write(data); out.write("\n".data(using: .utf8)!) }
}
