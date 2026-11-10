import QtQuick 2.12
import QtQuick.Layouts 1.12
import QtMultimedia 5.12
import Lomiri.Components 1.3 as UITK
import io.thp.pyotherside 1.3

UITK.Page {
    id: qrPage
    signal qrDecoded(string text)

    property bool scanning: true
    property bool decoding: false
    property bool capturingStill: false
    property bool torchOn: false
    property string tmpDir: ""
    property int frameCounter: 0

    header: UITK.PageHeader {
        id: pageHeader
        title: i18n.tr("Scan QR code")
        trailingActionBar.actions: [
            UITK.Action {
                iconName: "close"
                onTriggered: closePage()
            },
            UITK.Action {
                iconName: torchOn ? "flash-on" : "flash-off"
                text: i18n.tr("Light")
                visible: !camera.flash.supportedModes || camera.flash.supportedModes.length > 1
                onTriggered: setTorch(!torchOn)
            }
        ]
    }

    Camera {
        id: camera
        captureMode: Camera.CaptureStillImage
        // Ubuntu Touch backends default to auto flash, which fires the LED on
        // every autofocus cycle. Start with the LED explicitly off.
        flash.mode: Camera.FlashOff

        focus {
            // Continuous AF where available, otherwise single-shot AF that we
            // re-trigger periodically (refocusTimer) and on tap.
            focusMode: Camera.FocusContinuous
            focusPointMode: Camera.FocusPointCenter
        }

        imageCapture {
            onImageSaved: {
                capturingStill = false
                decodeImage(path, null)
            }
            onCaptureFailed: {
                capturingStill = false
                decoding = false
                statusText.text = i18n.tr("Photo failed, try again")
            }
        }

        onCameraStatusChanged: {
            if (cameraStatus === Camera.ActiveStatus) {
                configureFocus()
                applyFlash()
                camera.searchAndLock()
            }
        }

        onLockStatusChanged: {
            // some backends reset the flash mode during an AF cycle
            applyFlash()
            if (lockStatus === Camera.Locked) {
                focusIndicator.color = "#4caf50"
            } else if (lockStatus === Camera.Searching) {
                focusIndicator.color = "white"
            }
        }
    }

    VideoOutput {
        id: videoOutput
        anchors.fill: parent
        anchors.topMargin: pageHeader.height
        source: camera
        autoOrientation: true
        fillMode: VideoOutput.PreserveAspectCrop

        // Tap anywhere to focus on that point, pinch to zoom
        PinchArea {
            anchors.fill: parent
            property real startZoom: 1.0
            onPinchStarted: startZoom = camera.digitalZoom
            onPinchUpdated: setZoom(startZoom * pinch.scale)
            MouseArea {
                anchors.fill: parent
                onClicked: focusAt(mouse.x, mouse.y)
            }
        }
    }

    Rectangle {
        id: scanFrame
        width: Math.min(videoOutput.width, videoOutput.height) * 0.7
        height: width
        x: videoOutput.x + (videoOutput.width - width) / 2
        y: videoOutput.y + (videoOutput.height - height) / 2
        color: "transparent"
        border.width: units.gu(0.3)
        border.color: "white"
        radius: units.gu(1)
    }

    Rectangle {
        id: focusIndicator
        width: units.gu(6)
        height: width
        radius: width / 2
        color: "white"
        opacity: 0
        visible: opacity > 0
        border.width: units.gu(0.3)
        border.color: color
        Rectangle {
            anchors.fill: parent
            anchors.margins: units.gu(0.3)
            radius: width / 2
            color: "transparent"
        }
        NumberAnimation on opacity {
            id: focusFade
            running: false
            from: 0.9
            to: 0
            duration: 1200
        }
    }

    Column {
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: parent.bottom
        anchors.bottomMargin: units.gu(2)
        width: parent.width - units.gu(4)
        spacing: units.gu(1)

        Text {
            id: statusText
            width: parent.width
            wrapMode: Text.WordWrap
            text: i18n.tr("Hold the QR code 15–25 cm away. Tap to focus, pinch to zoom.")
            color: "white"
            style: Text.Outline
            styleColor: "black"
            font.pixelSize: units.gu(1.7)
            horizontalAlignment: Text.AlignHCenter
        }

        RowLayout {
            width: parent.width
            visible: camera.maximumDigitalZoom > 1.0
            spacing: units.gu(1)
            Text {
                text: "1×"
                color: "white"
                style: Text.Outline
                styleColor: "black"
            }
            UITK.Slider {
                id: zoomSlider
                Layout.fillWidth: true
                minimumValue: 1.0
                maximumValue: Math.min(camera.maximumDigitalZoom, 4.0)
                value: camera.digitalZoom
                live: true
                function formatValue(v) { return v.toFixed(1) + "×" }
                onValueChanged: {
                    if (pressed) {
                        setZoom(value)
                    }
                }
            }
            Text {
                text: zoomSlider.maximumValue.toFixed(0) + "×"
                color: "white"
                style: Text.Outline
                styleColor: "black"
            }
        }

        UITK.Button {
            anchors.horizontalCenter: parent.horizontalCenter
            text: i18n.tr("Take photo")
            enabled: !capturingStill && tmpDir.length > 0
                     && camera.imageCapture.ready
            onClicked: captureStill()
        }

        UITK.ActivityIndicator {
            running: decoding || capturingStill
            visible: running
            anchors.horizontalCenter: parent.horizontalCenter
        }
    }

    // Periodically scan the live preview
    Timer {
        id: captureTimer
        interval: 700
        repeat: true
        running: scanning && tmpDir.length > 0
                 && camera.cameraStatus === Camera.ActiveStatus
                 && !decoding && !capturingStill
        onTriggered: grabFrame()
    }

    // Many Ubuntu Touch camera backends don't really do continuous AF for
    // the viewfinder, so re-trigger an autofocus cycle regularly.
    Timer {
        id: refocusTimer
        interval: 3000
        repeat: true
        running: scanning && camera.cameraStatus === Camera.ActiveStatus
                 && !capturingStill
        onTriggered: {
            if (camera.lockStatus !== Camera.Searching) {
                camera.unlock()
                camera.searchAndLock()
            }
        }
    }

    function configureFocus() {
        var f = camera.focus
        if (f.isFocusModeSupported(Camera.FocusContinuous)) {
            f.focusMode = Camera.FocusContinuous
        } else if (f.isFocusModeSupported(Camera.FocusAuto)) {
            f.focusMode = Camera.FocusAuto
        } else if (f.isFocusModeSupported(Camera.FocusMacro)) {
            f.focusMode = Camera.FocusMacro
        }
        if (f.isFocusPointModeSupported(Camera.FocusPointCenter)) {
            f.focusPointMode = Camera.FocusPointCenter
        }
    }

    function focusAt(px, py) {
        // px/py are in videoOutput coordinates
        focusIndicator.x = videoOutput.x + px - focusIndicator.width / 2
        focusIndicator.y = videoOutput.y + py - focusIndicator.height / 2
        focusIndicator.color = "white"
        focusFade.restart()

        var f = camera.focus
        if (f.isFocusPointModeSupported(Camera.FocusPointCustom)) {
            var p = videoOutput.mapPointToSourceNormalized(Qt.point(px, py))
            f.customFocusPoint = p
            f.focusPointMode = Camera.FocusPointCustom
        }
        camera.unlock()
        camera.searchAndLock()
        refocusTimer.restart()
    }

    function setZoom(z) {
        var maxZ = Math.min(camera.maximumDigitalZoom, 4.0)
        camera.digitalZoom = Math.max(1.0, Math.min(maxZ, z))
    }

    function torchMode() {
        var modes = camera.flash.supportedModes
        var candidates = [Camera.FlashVideoLight, Camera.FlashTorch, Camera.FlashOn]
        if (!modes || modes.length === 0) {
            return Camera.FlashVideoLight
        }
        for (var i = 0; i < candidates.length; i++) {
            if (modes.indexOf(candidates[i]) !== -1) {
                return candidates[i]
            }
        }
        return Camera.FlashVideoLight
    }

    function desiredFlashMode() {
        return torchOn ? torchMode() : Camera.FlashOff
    }

    function applyFlash() {
        var want = desiredFlashMode()
        if (camera.flash.mode !== want) {
            camera.flash.mode = want
        }
    }

    function setTorch(on) {
        torchOn = on
        applyFlash()
    }

    // Re-assert our choice whenever the backend changes the mode on its own
    Connections {
        target: camera.flash
        onFlashModeChanged: {
            if (scanning && camera.flash.mode !== desiredFlashMode()) {
                camera.flash.mode = desiredFlashMode()
            }
        }
    }

    // Normalized rect of the scan frame within the grabbed preview image
    function frameCrop() {
        if (videoOutput.width <= 0 || videoOutput.height <= 0) {
            return null
        }
        return [
            (scanFrame.x - videoOutput.x) / videoOutput.width,
            (scanFrame.y - videoOutput.y) / videoOutput.height,
            scanFrame.width / videoOutput.width,
            scanFrame.height / videoOutput.height
        ]
    }

    function grabFrame() {
        if (!videoOutput.grabToImage) {
            return
        }
        decoding = true
        frameCounter = (frameCounter + 1) % 4
        var tmpPath = tmpDir + "/frame_" + frameCounter + ".png"

        // Grab at the native preview resolution if it is higher than the
        // on-screen size, so we don't throw away detail.
        var k = 1.0
        if (videoOutput.contentRect.width > 0 && videoOutput.sourceRect.width > 0) {
            k = videoOutput.sourceRect.width / videoOutput.contentRect.width
        }
        k = Math.max(1.0, Math.min(k, 2.0))
        var crop = frameCrop()
        var ok = videoOutput.grabToImage(function(result) {
            if (!scanning || !result || !result.saveToFile(tmpPath)) {
                decoding = false
                return
            }
            decodeImage(tmpPath, crop)
        }, Qt.size(Math.round(videoOutput.width * k), Math.round(videoOutput.height * k)))
        if (!ok) {
            decoding = false
        }
    }

    function captureStill() {
        capturingStill = true
        decoding = true
        applyFlash()
        statusText.text = i18n.tr("Focusing…")
        camera.searchAndLock()
        stillDelay.restart()
    }

    Timer {
        id: stillDelay
        interval: 900
        onTriggered: {
            statusText.text = i18n.tr("Decoding photo…")
            camera.imageCapture.captureToLocation(tmpDir + "/still.jpg")
        }
    }

    function decodeImage(path, crop) {
        var cleanPath = path
        if (cleanPath.indexOf("file://") === 0) {
            cleanPath = cleanPath.substring(7)
        }
        python.call('vpn.instance.decode_qr_image', [cleanPath, crop], function(result) {
            cleanupTemp(cleanPath)
            if (!scanning) {
                decoding = false
                return
            }
            if (result.error) {
                decoding = false
                if (result.error === "NO_QR") {
                    if (crop === null) {
                        statusText.text = i18n.tr("No QR code found in photo. Try again or zoom in.")
                    }
                    return
                }
                statusText.text = i18n.tr("Could not decode QR")
                toast.show(i18n.tr("QR error: ") + result.error)
                return
            }
            decoding = false
            stopCamera()
            qrPage.qrDecoded(result.text)
            pageStack.pop()
        })
    }

    function cleanupTemp(path) {
        if (!path || !python) {
            return
        }
        python.call('vpn.instance.delete_temp_file', [path], function() {})
    }

    function stopCamera() {
        scanning = false
        captureTimer.stop()
        refocusTimer.stop()
        stillDelay.stop()
        torchOn = false
        camera.flash.mode = Camera.FlashOff
        camera.stop()
    }

    function closePage() {
        if (!scanning) {
            return
        }
        stopCamera()
        pageStack.pop()
    }

    Component.onCompleted: {
        camera.start()
    }

    Component.onDestruction: {
        if (scanning) {
            stopCamera()
        }
    }

    Python {
        id: python
        Component.onCompleted: {
            addImportPath(Qt.resolvedUrl('../../src/'))
            importModule('vpn', function () {
                python.call('vpn.instance.get_qr_tmp_dir', [], function(result) {
                    if (result && !result.error) {
                        qrPage.tmpDir = result.path
                    } else {
                        toast.show(i18n.tr("QR error: ") + (result ? result.error : ""))
                    }
                })
            })
        }
    }
}
