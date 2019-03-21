# transformer = GenericUnivariateSelect(chi2, 'k_best', param=30)
# X_new = transformer.fit_transform(final, target)
# print('New shape: ', X_new.shape)
# feature_indices = transformer.get_support(indices=True)
# feature_names = [final.columns[idx]
#                  for idx, _
#                  in enumerate(final)
#                  if idx
#                  in feature_indices]
#
# removed_features = list(np.setdiff1d(final.columns, feature_names))
# print("Found {0} low-variance columns.".format(len(removed_features)))
# print('Best selected features: ', feature_names.__len__())
# print(feature_names)