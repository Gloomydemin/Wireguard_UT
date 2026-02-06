import QtQuick 2.0
import Lomiri.Components 1.3 as UITK
import io.thp.pyotherside 1.3
import Qt.labs.settings 1.0

import "../components"

UITK.Page {
    id: settingsPage

    Settings {
        id: settings
        property bool finishedWizard: false
        property bool useUserspace: true
        property bool canUseKmod: false
        property bool allowExternalControl: false
    }

    property string versionLabel: "WireGuard для Ubuntu Touch"
    property string backendLabel: ""

    Toast { id: toast }

    header: UITK.PageHeader {
        id: header
        title: i18n.tr("Настройки")

        leadingActionBar.actions: [
            UITK.Action {
                iconName: "back"
                onTriggered: {
                    stack.clear()
                    stack.push(Qt.resolvedUrl("PickProfilePage.qml"))
                }
            }
        ]
    }

    Flickable {
        id: flick
        anchors.top: header.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        property int pad: units.gu(2)
        contentWidth: flick.width
        contentHeight: contentCol.implicitHeight + pad * 2
        flickableDirection: Flickable.VerticalFlick
        boundsBehavior: Flickable.StopAtBounds
        clip: true

        Column {
            id: contentCol
            x: flick.pad
            y: flick.pad
            width: flick.width - flick.pad * 2
            spacing: units.gu(2)
            clip: false

            Rectangle {
                width: contentCol.width
                color: "#1f1f1f"
                radius: units.gu(1)
                border.color: "#2b2b2b"
                border.width: 1
                property int pad: units.gu(2.4)
                height: Math.max(cardRow.implicitHeight + pad * 2, units.gu(7))
                Row {
                    id: cardRow
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.leftMargin: parent.pad
                    anchors.rightMargin: parent.pad
                    spacing: units.gu(1.2)

                    Image {
                        source: Qt.resolvedUrl("../../assets/logo.png")
                        width: units.gu(5)
                        height: width
                        fillMode: Image.PreserveAspectFit
                    }
                    Column {
                        spacing: units.gu(0.4)
                        width: contentCol.width - units.gu(9)
                        UITK.Label {
                            id: titleLbl
                            text: versionLabel
                            color: "white"
                            font.pixelSize: units.gu(2.0)
                            font.bold: true
                            wrapMode: Text.WordWrap
                        }
                        UITK.Label {
                            id: backendLbl
                            text: backendLabel
                            color: "#cccccc"
                            wrapMode: Text.WordWrap
                        }
                    }
                }
            }

            SettingsItem {
                title: i18n.tr("Экспорт туннелей в zip-файл")
                description: i18n.tr("Zip-файл будет сохранен в папке загрузок")
                onClicked: {
                    python.call('vpn.instance.export_confs_zip', [], function(res) {
                        if (res.error) {
                            toast.show(i18n.tr("Ошибка экспорта: ") + res.error)
                        } else {
                            toast.show(i18n.tr("Сохранено: ") + res.path)
                        }
                    })
                }
            }

            SettingsItem {
                title: i18n.tr("Просмотр журналов приложения")
                description: i18n.tr("Журналы могут помочь при отладке")
                onClicked: Qt.openUrlExternally("file:///home/phablet/.cache/wireguard.sysadmin/")
            }

            SettingsItem {
                title: i18n.tr("Использовать userspace реализацию")
                description: i18n.tr("Может быть медленнее и менее стабильной")
                control: UITK.Switch {
                    enabled: settings.canUseKmod
                    checked: settings.useUserspace
                    onCheckedChanged: {
                        settings.useUserspace = checked
                        if (typeof root !== "undefined" && root.settings) {
                            root.settings.useUserspace = checked
                        }
                    }
                }
            }

            SettingsItem {
                title: i18n.tr("Разрешить управление через внешние приложения")
                description: i18n.tr("Пока не реализовано")
                control: null
                descColor: "#ffb400"
            }

            SettingsItem {
                title: i18n.tr("Повторно проверить модуль ядра")
                description: i18n.tr("Запустить мастер проверки ядра и прав sudo")
                onClicked: {
                    stack.clear()
                    stack.push(Qt.resolvedUrl("WizardPage.qml"))
                }
            }

            SettingsItem {
                title: i18n.tr("Исходники и багтрекер")
                description: i18n.tr("Открыть репозиторий проекта")
                onClicked: Qt.openUrlExternally("https://github.com/Gloomydemin/Wireguard_qml")
            }

            Rectangle { height: units.gu(2); width: 1; color: "transparent" }
        }
    }

    Python {
        id: python
        Component.onCompleted: {
            addImportPath(Qt.resolvedUrl('../../src/'))
            importModule('vpn', function () {
                python.call('vpn.instance.get_wireguard_version', [], function(res) {
                    var ver = res && res.version ? res.version : ""
                    versionLabel = "WireGuard для Ubuntu Touch "
                    backendLabel = res && res.backend ? res.backend : ""
                })
            })
        }
    }
}
