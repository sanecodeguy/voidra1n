// swift-tools-version: 6.0
import PackageDescription
let package = Package(
    name: "AIOExploit",
    platforms: [.iOS(.v17)],
    products: [
        .library(name: "AIOExploit", targets: ["AIOExploit"]),
    ],
    targets: [
        .target(
            name: "CExploit",
            path: "Sources/CExploit",
            publicHeadersPath: "include"
        ),
        .target(
            name: "AIOExploit",
            dependencies: ["CExploit"],
            path: "Sources/AIOExploit",
            resources: [.copy("AppIcon.png"), .copy("BrandImage.png")]
        ),
    ]
)
