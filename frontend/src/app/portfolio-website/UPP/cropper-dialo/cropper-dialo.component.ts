import { CommonModule } from '@angular/common';
import { Component, importProvidersFrom, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog';
import { ImageCroppedEvent } from 'ngx-image-cropper';
import { ImageCropperComponent } from 'ngx-image-cropper';
  
 

export type CropperDialoData = {
  image: File;
  width: number;
  height: number;
}

export type CropperDialoResult = {
  blob: Blob;
  imageUrl: string;
}
@Component({
  selector: 'app-cropper-dialo',
  standalone: true,
  imports: [CommonModule, ImageCropperComponent, MatDialogModule, MatButtonModule],
  templateUrl: './cropper-dialo.component.html',
  styleUrl: './cropper-dialo.component.scss'
})
export class CropperDialoComponent {
  data: CropperDialoData = inject(MAT_DIALOG_DATA);

  result = signal<CropperDialoResult | undefined>(undefined);

  imageCropped(event: ImageCroppedEvent){
    const { blob, objectUrl } = event;
    if (blob && objectUrl){
      this.result.set({ blob, imageUrl: objectUrl});
    }

  }

}
