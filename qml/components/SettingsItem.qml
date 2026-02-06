import QtQuick 2.0
import QtQuick.Layouts 1.0
import Lomiri.Components 1.3 as UITK

Item {
    id: settingsItem
    property alias title: titleLabel.text
    property alias description: descLabel.text
    property alias control: controlLoader.sourceComponent
    property color descColor: "#ccc"
    signal clicked

    width: parent ? parent.width : implicitWidth
    readonly property int pad: units.gu(1.2)
    implicitHeight: Math.max(titleLabel.implicitHeight + descLabel.implicitHeight + pad * 2,
                             controlLoader.implicitHeight + pad * 2)

    Rectangle {
        anchors.fill: parent
        color: "transparent"
    }

    RowLayout {
        anchors.fill: parent
        anchors.margins: pad
        spacing: units.gu(1.2)

        ColumnLayout {
            Layout.fillWidth: true
            spacing: units.gu(0.2)
            UITK.Label {
                id: titleLabel
                Layout.fillWidth: true
                font.pixelSize: units.gu(2)
                wrapMode: Text.WordWrap
            }
            UITK.Label {
                id: descLabel
                Layout.fillWidth: true
                color: settingsItem.descColor
                wrapMode: Text.WordWrap
            }
        }

        Loader {
            id: controlLoader
            Layout.alignment: Qt.AlignVCenter
            height: item ? item.implicitHeight : units.gu(3)
            width: item ? item.implicitWidth : units.gu(6)
        }
    }

    MouseArea {
        anchors.fill: parent
        enabled: controlLoader.sourceComponent === null
        onClicked: settingsItem.clicked()
    }
}
