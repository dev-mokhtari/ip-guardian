import AppKit
import Foundation

/// Flags ship inside the app.
///
/// They used to be fetched from a CDN, which failed outright behind a proxy
/// that did not route that host, and told a third party which country the user
/// was connected through every time it changed — the one fact this app exists
/// to keep quiet. Every flag in the world costs well under a megabyte, so the
/// network was buying nothing.
enum CountryFlagImage {
    private static let cache = NSCache<NSString, NSImage>()
    static let directoryName = "Flags"

    static func fileName(for countryCode: String?) -> String? {
        CountryCode.normalized(countryCode).map { "\($0.lowercased()).png" }
    }

    /// Answers "is there a flag for this country" without decoding one.
    /// Deciding it by loading the image cost 134 ms across the whole list and
    /// left every flag sitting in the cache; a lookup costs under 3 ms.
    static func exists(for countryCode: String?) -> Bool {
        guard let code = CountryCode.normalized(countryCode) else { return false }
        return Bundle.main.url(
            forResource: code.lowercased(),
            withExtension: "png",
            subdirectory: directoryName
        ) != nil
    }

    static func image(for countryCode: String?) -> NSImage? {
        guard let code = CountryCode.normalized(countryCode) else { return nil }

        if let cached = cache.object(forKey: code as NSString) { return cached }
        guard let url = Bundle.main.url(
            forResource: code.lowercased(),
            withExtension: "png",
            subdirectory: directoryName
        ), let image = NSImage(contentsOf: url) else {
            // A missing flag leaves the section plain, exactly as before.
            return nil
        }

        cache.setObject(image, forKey: code as NSString)
        return image
    }
}
