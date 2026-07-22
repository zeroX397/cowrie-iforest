from typing import List

import joblib
import pandas as pd


class IsolationForestPredictor:
    def __init__(
        self,
        model_path: str,
        imputer_path: str,
        feature_columns_path: str,
        threshold_path: str,
    ):
        self.model = joblib.load(model_path)
        self.imputer = joblib.load(imputer_path)
        self.feature_columns: List[str] = joblib.load(feature_columns_path)
        self.threshold = self._load_threshold(threshold_path)

    def _load_threshold(self, threshold_path: str) -> float:
        threshold_object = joblib.load(threshold_path)

        if isinstance(threshold_object, dict):
            for key in [
                "threshold",
                "threshold_anomaly_score",
                "anomaly_score_threshold",
            ]:
                if key in threshold_object:
                    return float(threshold_object[key])

        return float(threshold_object)

    def _prepare_features(self, dataframe: pd.DataFrame) -> pd.DataFrame:
        """
        Menyiapkan fitur prediksi agar sama dengan fitur saat training.

        Tahapan:
        1. Menambahkan kolom fitur yang belum ada dengan nilai 0.
        2. Mengurutkan kolom sesuai feature_columns.pkl.
        3. Mengubah semua nilai menjadi numerik.
        4. Melakukan preprocessing menggunakan SimpleImputer hasil training.
        5. Mengembalikan hasil imputasi sebagai DataFrame agar nama kolom tetap ada.
        """
        prepared = dataframe.copy()

        for column in self.feature_columns:
            if column not in prepared.columns:
                prepared[column] = 0

        prepared = prepared[self.feature_columns]
        prepared = prepared.apply(pd.to_numeric, errors="coerce")

        # Penting:
        # Saat prediksi gunakan transform(), bukan fit_transform().
        transformed = self.imputer.transform(prepared)

        # SimpleImputer.transform() menghasilkan numpy array.
        # Ubah kembali menjadi DataFrame agar Isolation Forest menerima
        # nama kolom yang sama seperti saat training.
        transformed_dataframe = pd.DataFrame(
            transformed,
            columns=self.feature_columns,
            index=prepared.index,
        )

        return transformed_dataframe

    def predict(self, dataframe: pd.DataFrame) -> pd.DataFrame:
        if dataframe.empty:
            return dataframe

        result = dataframe.copy()

        features = self._prepare_features(result)

        # Saat training, anomaly_score dibuat agar nilai yang lebih besar
        # berarti semakin anomali. Karena itu score_samples dibalik.
        score_samples = self.model.score_samples(features)
        anomaly_scores = -score_samples

        result["anomaly_score"] = anomaly_scores
        result["threshold_anomaly_score"] = self.threshold
        result["is_anomaly"] = (
            result["anomaly_score"] >= self.threshold
        ).astype(int)

        return result
