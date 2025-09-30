#if UNITY_EDITOR
using UnityEditor;
using UnityEngine;

namespace TeamBuddies.Gameplay.Editor
{
    public sealed class PadSpawnAuthoringWindow : EditorWindow
    {
        private VehicleSpawnPadData padData;
        private Vector2 scrollPosition;
        private SerializedObject serializedPad;

        [MenuItem("Team Buddies/Pad Spawn Authoring", priority = 1000)]
        public static void Open()
        {
            GetWindow<PadSpawnAuthoringWindow>("Pad Spawn Authoring").Show();
        }

        private void OnEnable()
        {
            RefreshSerializedObject();
        }

        private void OnSelectionChange()
        {
            if (Selection.activeObject is VehicleSpawnPadData data && data != padData)
            {
                padData = data;
                RefreshSerializedObject();
                Repaint();
            }
        }

        private void OnGUI()
        {
            EditorGUILayout.Space();
            DrawPadPicker();

            if (padData == null)
            {
                DrawCreateButton();
                return;
            }

            serializedPad.UpdateIfRequiredOrScript();

            scrollPosition = EditorGUILayout.BeginScrollView(scrollPosition);
            EditorGUILayout.PropertyField(serializedPad.FindProperty("padName"));
            EditorGUILayout.PropertyField(serializedPad.FindProperty("findingsNotes"));
            EditorGUILayout.Space();

            EditorGUILayout.LabelField("Vertical Integrator Seed", EditorStyles.boldLabel);
            EditorGUILayout.PropertyField(serializedPad.FindProperty("globalBaseY"));
            EditorGUILayout.PropertyField(serializedPad.FindProperty("initialPosY"));
            EditorGUILayout.PropertyField(serializedPad.FindProperty("initialVelY"));
            EditorGUILayout.PropertyField(serializedPad.FindProperty("secIdx30Delta"));
            EditorGUILayout.PropertyField(serializedPad.FindProperty("secHandle0x40"));
            EditorGUILayout.PropertyField(serializedPad.FindProperty("secFlag0x60"));
            EditorGUILayout.PropertyField(serializedPad.FindProperty("fallbackMode"));
            EditorGUILayout.Space();

            EditorGUILayout.LabelField("Spawn Gate Observations", EditorStyles.boldLabel);
            EditorGUILayout.PropertyField(serializedPad.FindProperty("throttleIncrement"));
            EditorGUILayout.PropertyField(serializedPad.FindProperty("hudByteRange"));
            EditorGUILayout.PropertyField(serializedPad.FindProperty("overlayStubAddress"));
            EditorGUILayout.PropertyField(serializedPad.FindProperty("overlayHudAddress"));
            EditorGUILayout.PropertyField(serializedPad.FindProperty("seats"), includeChildren: true);

            EditorGUILayout.EndScrollView();

            if (serializedPad.ApplyModifiedProperties())
            {
                EditorUtility.SetDirty(padData);
            }

            EditorGUILayout.Space();
            DrawApplySection();
        }

        private void DrawPadPicker()
        {
            using (new EditorGUILayout.HorizontalScope())
            {
                var next = (VehicleSpawnPadData)EditorGUILayout.ObjectField("Pad Asset", padData, typeof(VehicleSpawnPadData), false);
                if (next != padData)
                {
                    padData = next;
                    RefreshSerializedObject();
                }

                if (padData != null && GUILayout.Button("Ping", GUILayout.Width(60)))
                {
                    EditorGUIUtility.PingObject(padData);
                }
            }
        }

        private void DrawCreateButton()
        {
            EditorGUILayout.HelpBox("Select an existing VehicleSpawnPadData asset or create a new one to start mirroring RE findings.", MessageType.Info);
            if (GUILayout.Button("Create Pad Data Asset"))
            {
                var asset = CreateInstance<VehicleSpawnPadData>();
                var path = EditorUtility.SaveFilePanelInProject(
                    "Create Vehicle Spawn Pad Data",
                    "VehicleSpawnPadData",
                    "asset",
                    "Choose a location inside the project to store the pad data snapshot.");

                if (!string.IsNullOrEmpty(path))
                {
                    AssetDatabase.CreateAsset(asset, path);
                    AssetDatabase.SaveAssets();
                    Selection.activeObject = asset;
                    padData = asset;
                    RefreshSerializedObject();
                }
            }
        }

        private void DrawApplySection()
        {
            using (new EditorGUILayout.VerticalScope(EditorStyles.helpBox))
            {
                EditorGUILayout.LabelField("Push To Scene", EditorStyles.boldLabel);
                EditorGUILayout.LabelField("Select GameObjects with VerticalIntegrator components and press Apply.", EditorStyles.wordWrappedMiniLabel);

                using (new EditorGUI.DisabledScope(Selection.gameObjects.Length == 0))
                {
                    if (GUILayout.Button("Apply Pad Data To Selection"))
                    {
                        ApplyToSelection();
                    }
                }
            }
        }

        private void ApplyToSelection()
        {
            if (padData == null)
            {
                return;
            }

            foreach (var gameObject in Selection.gameObjects)
            {
                var integrator = gameObject.GetComponent<VerticalIntegrator>();
                if (integrator == null)
                {
                    continue;
                }

                Undo.RecordObject(integrator, "Apply Pad Data");
                padData.ApplyTo(integrator, overwriteRuntimeState: true);
                EditorUtility.SetDirty(integrator);
            }
        }

        private void RefreshSerializedObject()
        {
            serializedPad = padData != null ? new SerializedObject(padData) : null;
        }
    }
}
#endif
